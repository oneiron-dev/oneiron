"""Transcript-conditioned Ukrainian CTC word alignment, not ASR or qualification.

The operator supplies an immutable Ukrainian Wav2Vec2 CTC snapshot. This module
uses actual acoustic emissions and the standard CTC state recurrence. It never
interpolates unaligned words, substitutes Russian, or fetches a model/tokenizer.
"""
from __future__ import annotations
import math
import re
import unicodedata

MAX_CELLS = 32_000_000
UK_LETTERS = set("абвгґдеєжзиіїйклмнопрстуфхцчшщьюя")


def transcript_tokens(text, vocabulary, blank, error):
    words = re.findall(r"\S+", text)
    tokens, owners = [], []
    if not words or not UK_LETTERS <= vocabulary.keys() or "|" not in vocabulary:
        raise error("UnsupportedCtcVocabulary")
    for index, word in enumerate(words):
        if index:
            tokens.append(vocabulary["|"])
            owners.append(None)
        count = 0
        for character in unicodedata.normalize("NFC", word).lower():
            if character in "’ʼ‘＇":
                character = "'"
            if character in UK_LETTERS or character in "'-":
                if character not in vocabulary or vocabulary[character] == blank:
                    raise error("UnalignableTranscript")
                tokens.append(vocabulary[character])
                owners.append(index)
                count += int(character in UK_LETTERS)
            elif unicodedata.category(character).startswith("P"):
                # Unspoken punctuation stays attached to its original word.
                # It receives no independently asserted acoustic token boundary.
                continue
            else:
                raise error("UnalignableTranscript")
        if not count:
            raise error("UnalignableTranscript")
    if any(type(token) is not int or token < 0 or token == blank for token in tokens):
        raise error("UnsupportedCtcVocabulary")
    return words, tokens, owners


def token_spans(emissions, tokens, blank, error):
    frames = len(emissions)
    if not frames or not tokens:
        raise error("CtcAlignmentUnavailable")
    width = len(emissions[0])
    if (type(blank) is not int or not 0 <= blank < width
            or any(type(token) is not int or not 0 <= token < width or token == blank for token in tokens)
            or any(len(row) != width or any(not math.isfinite(v) for v in row) for row in emissions)):
        raise error("InvalidCtcEmissions")
    states = [blank]
    for token in tokens:
        states.extend([token, blank])
    size = len(states)
    if frames * size > MAX_CELLS:
        raise error("CtcAlignmentTooLarge")
    if frames < len(tokens) + sum(a == b for a, b in zip(tokens, tokens[1:])):
        raise error("CtcAlignmentUnavailable")
    trace = bytearray(frames * size)
    previous = [float("-inf")] * size
    previous[0] = 0.0
    for frame, emission in enumerate(emissions):
        current = [float("-inf")] * size
        for state, label in enumerate(states):
            best, step = previous[state], 0
            if state and previous[state - 1] > best:
                best, step = previous[state - 1], 1
            if state > 1 and label != blank and label != states[state - 2] and previous[state - 2] > best:
                best, step = previous[state - 2], 2
            current[state] = best + emission[label]
            trace[frame * size + state] = step
        previous = current
    state = size - 1 if previous[-1] >= previous[-2] else size - 2
    if not math.isfinite(previous[state]):
        raise error("CtcAlignmentUnavailable")
    spans = [None] * len(tokens)
    for frame in range(frames - 1, -1, -1):
        if state % 2:
            token = state // 2
            spans[token] = (frame, spans[token][1] if spans[token] else frame + 1)
        state -= trace[frame * size + state]
    if state != 0 or any(span is None for span in spans):
        raise error("CtcAlignmentUnavailable")
    return spans


def word_spans(emissions, tokens, owners, words, blank, samples, error):
    spans = token_spans(emissions, tokens, blank, error)
    result = []
    for index, word in enumerate(words):
        own = [span for span, owner in zip(spans, owners) if owner == index]
        if not own:
            raise error("UnalignableTranscript")
        # Map the model's actual frame grid onto this exact PCM sample interval.
        # No missing token/word receives a time through interpolation.
        start = round(own[0][0] * samples * 1000 / (16000 * len(emissions)))
        end = round(own[-1][1] * samples * 1000 / (16000 * len(emissions)))
        if end <= start:
            raise error("InvalidAlignmentOutput")
        result.append({"start_ms": start, "end_ms": end, "text": word, "confidence": None})
    return result


def align(audio, text, snapshot, error):
    if not 400 <= len(audio) <= 16000 * 120:
        raise error("InvalidCtcAudio")
    import torch
    from transformers import Wav2Vec2ForCTC, Wav2Vec2Processor
    processor = Wav2Vec2Processor.from_pretrained(snapshot, local_files_only=True)
    model = Wav2Vec2ForCTC.from_pretrained(snapshot, local_files_only=True,
        use_safetensors=True, torch_dtype=torch.float32).to("cpu").eval()
    words, tokens, owners = transcript_tokens(text, processor.tokenizer.get_vocab(), model.config.pad_token_id, error)
    inputs = processor(audio, sampling_rate=16000, return_tensors="pt")
    with torch.inference_mode():
        logits = model(**inputs).logits[0]
        emissions = torch.log_softmax(logits, dim=-1).cpu().tolist()
    return word_spans(emissions, tokens, owners, words, model.config.pad_token_id, len(audio), error)
