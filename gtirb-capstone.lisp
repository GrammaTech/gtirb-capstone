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
(defpackage :gtirb-capstone/gtirb-capstone
  (:nicknames :gtirb-capstone)
  (:use :gt :gtirb :graph :capstone/clos :keystone/clos :stefil)
  (:shadowing-import-from :gtirb :address :bytes :symbol)
  (:shadow :size :size-t :version :architecture :mode :copy)
  (:export :instructions))
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
                                      (:ppc32 :ppc))
                      :mode (ecase (isa (first (modules object)))
                              (:x64 :64)
                              (:ia32 :32)
                              (:arm :arm)
                              (:ppc32 :32)))
                    (make-instance 'keystone-engine
                      :architecture (ecase (isa (first (modules object)))
                                      (:x64 :x86)
                                      (:ia32 :x86)
                                      (:arm :arm)
                                      (:ppc32 :ppc))
                      :mode (ecase (isa (first (modules object)))
                              (:x64 :64)
                              (:ia32 :32)
                              (:arm :arm)
                              (:ppc32 :32))))))))

(defgeneric instructions (object)
  (:documentation "Access the assembly instructions for OBJECT."))

(defmethod instructions ((object gtirb-byte-block))
  (destructuring-bind (cs . ks) (start-engines (ir object))
    (declare (ignorable ks))
    (disasm cs (bytes object))))


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
