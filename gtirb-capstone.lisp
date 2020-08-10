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
;;;
;;; TODO: Implement a universal S-expr syntax for instructions which
;;;       is able to be parsed from capstone output and printed to
;;;       keystone input.  Use this for instructions.
;;;
;;; TODO: Add accesses to add/remove/replace instructions at a
;;;       particular location in the byte range of a block.  This
;;;       should then invoke the appropriate location-specific byte
;;;       setter on that block, which should itself update subsequent
;;;       offsets in the block's byte-array (e.g. symbols).
;;;
(defpackage :gtirb-capstone/gtirb-capstone
  (:nicknames :gtirb-capstone)
  (:use :gt :gtirb :graph :capstone :keystone :stefil)
  (:shadowing-import-from :gtirb :address :bytes :symbol)
  (:shadow :size :size-t :version :architecture :mode :copy :test)
  (:shadowing-import-from :cffi :foreign-enum-value)
  (:shadowing-import-from :capstone/raw :cs-mode)
  (:export :instructions :set-syntax :asm :disasm :mnemonic))
(in-package :gtirb-capstone/gtirb-capstone)
(in-readtable :curry-compose-reader-macros)

(defvar *engines* (make-hash-table)
  "Cache Capstone and Keystone engines indexes by GTIRB instance.")

(defgeneric start-engines (object)
  (:documentation "Startup Capstone and Keystone engines for OBJECT.")
  (:method ((object gtirb))
    (or (gethash (uuid object) *engines*)
        (setf (gethash (uuid object) *engines*)
              (cons (make-instance 'capstone-engine
                      :architecture (ecase (isa (first (modules object)))
                                      (:x64 :x86)
                                      (:ia32 :x86)
                                      (:arm :arm)
                                      (:ppc32 :ppc)
                                      (:ppc64 :ppc))
                      :mode (ecase (isa (first (modules object)))
                              (:x64 :64)
                              (:ia32 :32)
                              (:arm :arm)
                              (:ppc32 (+ (foreign-enum-value 'cs-mode :big_endian)
                                         (foreign-enum-value 'cs-mode :32)))
                              (:ppc64 :64)))

                    (make-instance 'keystone-engine
                      :architecture (ecase (isa (first (modules object)))
                                      (:x64 :x86)
                                      (:ia32 :x86)
                                      (:arm :arm)
                                      (:ppc32 :ppc)
                                      (:ppc64 :ppc))
                      :mode (ecase (isa (first (modules object)))
                              (:x64 :64)
                              (:ia32 :32)
                              (:arm :arm)
                              (:ppc32 :ppc64)
                              (:ppc64 :ppc64)
                              )))))))

(defgeneric instructions (object)
  (:documentation "Access the assembly instructions for OBJECT.")
  (:method ((object gtirb-node))
    (destructuring-bind (cs . ks) (start-engines (ir object))
      (declare (ignorable ks))
      (disasm cs (bytes object)))))

(defgeneric set-syntax (object syntax)
  (:documentation "Set the assembly instruction syntax for OBJECT.")
  (:method ((object gtirb-node) syntax)
    (destructuring-bind (cs . ks) (start-engines (ir object))
      (declare (ignorable cs))
      (set-option ks :syntax syntax))))

(defmethod asm ((object gtirb-node) (code string) &key address)
  (destructuring-bind (cs . ks) (start-engines (ir object))
    (declare (ignorable cs))
    (asm ks code :address address)))

(defmethod disasm ((object gtirb-node) (bytes vector)
                   &key (address nil address-p) (count nil count-p))
  (destructuring-bind (cs . ks) (start-engines (ir object))
    (declare (ignorable ks))
    (apply #'disasm cs bytes (append (when address-p
                                       (list :address address))
                                     (when count-p
                                       (list :count count))))))

;;;; Main test suite.
(defsuite test)
(in-suite test)

(defvar *hello*)

(defvar *base-dir* (nest (make-pathname :directory)
                         (pathname-directory)
                         #.(or *compile-file-truename*
                               *load-truename*
                               *default-pathname-defaults*)))

(defixture hello
  (:setup (setf *hello* (read-gtirb (merge-pathnames "tests/hello.v1.gtirb"
                                                     *base-dir*))))
  (:teardown (setf *hello* nil)))

(deftest read-instructions ()
  (with-fixture hello
    (let ((instructions
           (instructions (get-uuid (first (nodes (cfg *hello*))) *hello*))))
      (is instructions)
      (is (every {typep _ 'capstone-instruction} instructions)))))
