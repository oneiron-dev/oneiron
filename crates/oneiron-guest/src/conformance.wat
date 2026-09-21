(component
  ;; This is a typed WAT fixture, not JavaScript and not QuickJS. It echoes
  ;; source bytes (or a fixed marker) only after a secret-free credential receipt.
  (type $credential-record (record
    (field "operation" string) (field "credential-handle" string) (field "args" string)))
  (import "credential-input" (type $credential-input (eq $credential-record)))
  (type $credential-type (func (param "input" $credential-input)
    (result (result string (error string)))))
  (import "credential-call" (func $credential (type $credential-type)))

  (type $time-shape (record (field "start" u64) (field "end" u64)))
  (import "time-range" (type $time (eq $time-shape)))
  (type $claim-shape (record
    (field "id" string) (field "predicate" string) (field "subject" string)
    (field "value" string) (field "confidence" (option f32))
    (field "occurred" (option $time)) (field "learned-at" (option u64))))
  (import "claim-input" (type $claim (eq $claim-shape)))
  (type $file-shape (record (field "path" string) (field "bytes" (list u8))))
  (import "file-proposal" (type $file (eq $file-shape)))
  (type $proposal-shape (variant (case "file-write" $file) (case "claim-candidate" $claim)))
  (import "proposal-delta" (type $proposal (eq $proposal-shape)))
  (type $step-shape (record (field "result-json" string) (field "proposals" (list $proposal))))
  (import "step-result" (type $step (eq $step-shape)))
  (type $run-type (func (param "source" string) (result (result $step (error string)))))

  (core module $storage
    (memory (export "memory") 32 32)
    (global $heap (mut i32) (i32.const 16384))
    (func (export "realloc") (param $old i32) (param $oldlen i32)
      (param $align i32) (param $len i32) (result i32)
      (local $ptr i32)
      (if (i32.eqz (local.get $len)) (then (return (i32.const 0))))
      (if (local.get $oldlen) (then unreachable))
      (local.set $ptr (i32.and
        (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1)))
        (i32.sub (i32.const 0) (local.get $align))))
      (global.set $heap (i32.add (local.get $ptr) (local.get $len)))
      (if (i32.gt_u (global.get $heap) (i32.const 2097152)) (then unreachable))
      (local.get $ptr))
    (data (i32.const 4096) "null")
    (data (i32.const 4128) "/mnt/workspace/result.txt")
    (data (i32.const 4192) "typed-component-conformance\0a")
    (data (i32.const 4256) "metadata")
    (data (i32.const 4288) "conformance-handle")
    (data (i32.const 4320) "{\22scheme\22:\22https\22,\22host\22:\22api.example.com\22}"))
  (core instance $storage-instance (instantiate $storage))
  (alias core export $storage-instance "memory" (core memory $memory))
  (alias core export $storage-instance "realloc" (core func $realloc))
  (core func $credential-lowered (canon lower (func $credential)
    (memory $memory) (realloc $realloc)))
  (core module $runner
    (import "host" "memory" (memory 32 32))
    ;; Flattened credential-input = three strings; result<string,string>
    ;; is returned indirectly through the seventh (return-area) argument.
    (import "host" "credential" (func $credential
      (param i32 i32 i32 i32 i32 i32 i32)))
    (func (export "run") (param $source i32) (param $length i32) (result i32)
      (call $credential
        (i32.const 4256) (i32.const 8) (i32.const 4288) (i32.const 18)
        (i32.const 4320) (i32.const 43) (i32.const 1536))
      (if (i32.load (i32.const 1536)) (then unreachable))
      ;; result<step-result,string>: discriminant, then the 16-byte record.
      (i32.store (i32.const 1024) (i32.const 0))
      (i32.store (i32.const 1028) (i32.const 4096))
      (i32.store (i32.const 1032) (i32.const 4))
      (i32.store (i32.const 1036) (i32.const 2048))
      (i32.store (i32.const 1040) (i32.const 1))
      ;; proposal-delta has 8-byte alignment from claim-input's u64 fields.
      ;; file-write payload starts 8 bytes after the variant discriminant.
      (i32.store (i32.const 2048) (i32.const 0))
      (i32.store (i32.const 2056) (i32.const 4128))
      (i32.store (i32.const 2060) (i32.const 25))
      (if (local.get $length)
        (then
          (i32.store (i32.const 2064) (local.get $source))
          (i32.store (i32.const 2068) (local.get $length)))
        (else
          (i32.store (i32.const 2064) (i32.const 4192))
          (i32.store (i32.const 2068) (i32.const 28))))
      (i32.const 1024)))
  (core instance $runner-instance (instantiate $runner
    (with "host" (instance
      (export "memory" (memory $memory))
      (export "credential" (func $credential-lowered))))))
  (func (export "run-step") (type $run-type)
    (canon lift (core func $runner-instance "run") (memory $memory) (realloc $realloc))))
