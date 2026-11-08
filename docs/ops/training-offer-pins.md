# Training-offer model pins

A `TrainRecipe` candidate names an existing run as `training_run:<run id>`.
Its `base.content_hash` is the lowercase hexadecimal BLAKE3 digest returned by
`PinnedCheckpoint::content_hash()` for that run's starting checkpoint. It binds
the model and the complete file set: each file's name, kind, repository, source
revision, actual content hash and byte count. File order does not affect it.
The run retains the full file pins in its plan. The separate `base.revision`
field still shows the first file's source revision; it is not the whole-set pin.

The Coach's draft and candidate validation use the same `training_base_pin`
helper. A change to a tokenizer, config, template, adapter or later weight shard
therefore changes the offered base pin even when the first file stays the same.
The offer base is a suggestion only (FIX 8207): the owner may prepare the run
from a different model or checkpoint. Plan validation checks the offer's seat
and role; the authorization handoff pins the owner's exact prepared spec, not
the suggested base. This does not read file bodies, run a pilot, authorize a
download or deploy a model.

Stock-model offers still name their registered backend's serving revision.
Their download-file inventory and the candidate/base licence text, source and
hash are not captured by this change. The existing licence string and its
catalog match remain unchanged.
