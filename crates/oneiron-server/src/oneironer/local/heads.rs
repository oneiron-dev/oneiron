//! The trained coreference ranker and turn-affect MLP. Neither owns an
//! encoder: both consume the one backbone pass made for the window.

use candle_core::{Module, Tensor};
use candle_nn::{Linear, VarBuilder, linear};
use oneiron::memory::extraction::{
    ContextLink, CorefLink, EncoderOutput, SpeakerLink, SpeakerRole, SpeakerTarget,
};

use super::window::{Span, Window, best_probability};

struct Mlp {
    first: Linear,
    last: Linear,
}

impl Mlp {
    fn load(
        vb: VarBuilder<'_>,
        input: usize,
        hidden: usize,
        output: usize,
    ) -> candle_core::Result<Self> {
        Ok(Self {
            first: linear(input, hidden, vb.pp("0"))?,
            last: linear(hidden, output, vb.pp("3"))?,
        })
    }

    fn forward(&self, input: &Tensor) -> candle_core::Result<Tensor> {
        self.last.forward(&self.first.forward(input)?.gelu_erf()?)
    }
}

pub(super) struct Affect(Mlp);

impl Affect {
    pub(super) fn load(
        vb: VarBuilder<'_>,
        width: usize,
        hidden: usize,
    ) -> candle_core::Result<Self> {
        Ok(Self(Mlp::load(vb.pp("head"), width, hidden, 3)?))
    }

    pub(super) fn infer(
        &self,
        hidden: &Tensor,
        window: &Window<'_>,
    ) -> anyhow::Result<Option<oneiron::affect::Vad>> {
        let positions: Vec<u32> = window
            .encoding
            .get_offsets()
            .iter()
            .enumerate()
            .filter_map(|(index, &(start, end))| {
                window
                    .segment(start, end)
                    .filter(|(_, segment)| segment.current)
                    .map(|_| index as u32)
            })
            .collect();
        if positions.is_empty() {
            return Ok(None);
        }
        let positions = Tensor::new(positions.as_slice(), hidden.device())?;
        let pooled = hidden.index_select(&positions, 0)?.mean_keepdim(0)?;
        let raw = self.0.forward(&pooled)?.flatten_all()?.to_vec1::<f32>()?;
        anyhow::ensure!(
            raw.iter().all(|value| value.is_finite()),
            "non-finite extraction affect"
        );
        Ok(Some(oneiron::affect::Vad {
            valence: raw[0].tanh(),
            arousal: sigmoid(raw[1]),
            dominance: sigmoid(raw[2]),
        }))
    }
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

pub(super) struct Coreference {
    projection: Linear,
    pseudo: Tensor,
    distance: Tensor,
    same_speaker: Tensor,
    pair: Mlp,
    new: Mlp,
    tau: f32,
}

struct Cluster {
    representations: Vec<Tensor>,
    last_turn: Option<usize>,
    speaker: Option<SpeakerRole>,
    antecedent: Option<usize>,
}

impl Coreference {
    pub(super) fn load(
        vb: VarBuilder<'_>,
        width: usize,
        repr: usize,
        tau: f32,
    ) -> candle_core::Result<Self> {
        Ok(Self {
            projection: linear(width, repr, vb.pp("mention_proj.0"))?,
            pseudo: vb.get((2, repr), "pseudo_emb.weight")?,
            distance: vb.get((8, 16), "dist_emb.weight")?,
            same_speaker: vb.get((2, 8), "same_speaker_emb.weight")?,
            pair: Mlp::load(vb.pp("pair_scorer"), repr * 3 + 24, repr, 1)?,
            new: Mlp::load(vb.pp("new_scorer"), repr, repr, 1)?,
            tau,
        })
    }

    pub(super) fn infer(
        &self,
        hidden: &Tensor,
        window: &Window<'_>,
        mentions: &[Span],
        coordinates: &std::collections::BTreeMap<(usize, usize, usize), usize>,
        output: &mut EncoderOutput,
    ) -> anyhow::Result<()> {
        let mut clusters = vec![
            Cluster {
                representations: vec![self.pseudo.narrow(0, 0, 1)?],
                last_turn: None,
                speaker: Some(SpeakerRole::User),
                antecedent: None,
            },
            Cluster {
                representations: vec![self.pseudo.narrow(0, 1, 1)?],
                last_turn: None,
                speaker: Some(SpeakerRole::Companion),
                antecedent: None,
            },
        ];
        for (index, mention) in mentions.iter().enumerate() {
            let segment = &window.segments[mention.segment];
            let pooled = hidden
                .narrow(
                    0,
                    mention.first_token,
                    mention.last_token - mention.first_token + 1,
                )?
                .mean_keepdim(0)?;
            let representation = self.projection.forward(&pooled)?.gelu_erf()?;
            let mut logits = Vec::with_capacity(clusters.len() + 1);
            for cluster in &clusters {
                let refs: Vec<&Tensor> = cluster.representations.iter().collect();
                let mean = Tensor::stack(&refs, 0)?.mean(0)?;
                let distance = cluster
                    .last_turn
                    .map_or(0, |turn| segment.turn_index.saturating_sub(turn));
                let bucket = [0, 1, 2, 3, 4, 7, 15]
                    .iter()
                    .position(|edge| distance <= *edge)
                    .unwrap_or(7);
                let same =
                    usize::from(segment.speaker.is_some() && segment.speaker == cluster.speaker);
                let distance = self.distance.narrow(0, bucket, 1)?;
                let speaker = self.same_speaker.narrow(0, same, 1)?;
                let product = (&representation * &mean)?;
                let features =
                    Tensor::cat(&[&representation, &mean, &product, &distance, &speaker], 1)?;
                logits.push(self.pair.forward(&features)?.to_vec2::<f32>()?[0][0]);
            }
            logits.push(self.new.forward(&representation)?.to_vec2::<f32>()?[0][0] + self.tau);
            let (predicted, confidence) = best_probability(&logits)?;
            if predicted == clusters.len() {
                clusters.push(Cluster {
                    representations: Vec::new(),
                    last_turn: None,
                    speaker: None,
                    antecedent: None,
                });
            }
            let cluster = &mut clusters[predicted];
            let key = (mention.segment, mention.start, mention.end);
            if segment.current
                && let Some(&span) = coordinates.get(&key)
            {
                if predicted < 2 {
                    if let Some(speaker) = segment.speaker {
                        // Pseudo-cluster identity stays A/B even after an
                        // addressee mention from the other side joins it.
                        let side = if predicted == 0 {
                            SpeakerRole::User
                        } else {
                            SpeakerRole::Companion
                        };
                        let target = if speaker == side {
                            SpeakerTarget::Speaker
                        } else {
                            SpeakerTarget::Addressee
                        };
                        output.speaker_links.push(SpeakerLink {
                            span,
                            target,
                            confidence,
                        });
                    }
                } else if let Some(antecedent) = cluster.antecedent {
                    let earlier = &mentions[antecedent];
                    let source = &window.segments[earlier.segment];
                    if source.current {
                        if let Some(&antecedent) =
                            coordinates.get(&(earlier.segment, earlier.start, earlier.end))
                            && antecedent < span
                        {
                            output.links.push(CorefLink {
                                span,
                                antecedent,
                                confidence: Some(confidence),
                            });
                        }
                    } else {
                        output.context_links.push(ContextLink {
                            span,
                            turn: source.turn.to_owned(),
                            message: source.message.id.clone(),
                            start: earlier.start - source.base + source.source_offset,
                            end: earlier.end - source.base + source.source_offset,
                            confidence,
                        });
                    }
                }
            }
            cluster.representations.push(representation);
            cluster.last_turn = Some(segment.turn_index);
            cluster.speaker = segment.speaker;
            cluster.antecedent = Some(index);
        }
        Ok(())
    }
}
