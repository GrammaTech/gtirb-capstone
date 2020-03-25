GTIRB-Capstone
==============

Integration between GTIRB and the Capstone/Keystone libraries.

## Abstract
GTIRB explicitly does not include any notion of instructions or
instruction semantics.  In general this is desirable as most tools
have their own intermediate languages and corresponding
encoders/decoders to deal with instructions.  However, in many cases
the high-quality Capstone/Keystone decoder/encoder libraries provide
sufficient instruction information for binary analysis and
transformation.  These libraries provide exceptional coverage of
multiple ISAs and are widely used.  GTIRB-Capstone integrates GTIRB
with the Capstone disassembler and the Keystone assembler allowing for
transparent access to instructions in GTIRB instances.
