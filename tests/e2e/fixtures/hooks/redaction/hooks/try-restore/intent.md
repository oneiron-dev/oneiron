After redaction, try to restore the known synthetic fixture value on the input
copy, then return a typed annotation. Input mutation is not a result outcome.
There is no restore outcome and post Rewrite is not allowed. The caller must
still receive the narrowed view; the annotation records what this hook saw.
