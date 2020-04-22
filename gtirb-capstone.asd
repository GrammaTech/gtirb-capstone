;;; Copyright (C) 2020 GrammaTech, Inc.
;;;
;;; This code is licensed under the MIT license. See the LICENSE file in
;;; the project root for license terms.
;;;
;;; This project is sponsored by the Office of Naval Research, One Liberty
;;; Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
;;; N68335-17-C-0700.  The content of the information does not necessarily
;;; reflect the position or policy of the Government and no official
;;; endorsement should be inferred.
(defsystem "gtirb-capstone"
    :name "gtirb-capstone"
    :author "GrammaTech"
    :licence "MIT"
    :description "Integration between GTIRB and the Capstone/Keystone libraries"
    :long-description "GTIRB explicitly does not include any notion of
instructions or instruction semantics.  In general this is desirable
as most tools have their own intermediate languages and corresponding
encoders/decoders to deal with instructions.  However, in many cases
the high-quality Capstone/Keystone decoder/encoder libraries provide
sufficient instruction information for binary analysis and
transformation.  These libraries provide exceptional coverage of
multiple ISAs and are widely used.  GTIRB-Capstone integrates GTIRB
with the Capstone disassembler and the Keystone assembler allowing for
transparent access to instructions in GTIRB instances."
    :depends-on (:gtirb-capstone/gtirb-capstone)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system)
    :perform
    (test-op (o c) (symbol-call :gtirb-capstone/gtirb-capstone '#:test)))

(register-system-packages "capstone" '(:capstone/raw))
