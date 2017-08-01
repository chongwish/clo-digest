;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA384 Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://en.wikipedia.org/wiki/SHA-2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha2.384
  (:use :cl)
  (:nicknames :clo-digest-sha2-384)
  (:import-from #:clo-digest.sha2.64bit
                #:base-text
                #:base-file)
  (:import-from #:clo-digest.base
                #:convert-string-to-byte)
  (:export #:text
           #:file))

(in-package #:clo-digest.sha2.384)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *sha2-magic-number-array* '#(#xcbbb9d5dc1059ed8 #x629a292a367cd507 #x9159015a3070dd17 #x152fecd8f70e5939 #x67332667ffc00b31 #x8eb44a8768581511 #xdb0c2e0d64f98fa7 #x47b5481dbefa4fa4)))

(defun text (str &key (encoding :utf8))
  "sha384sum string"
  (let ((a (svref *sha2-magic-number-array* 0))
        (b (svref *sha2-magic-number-array* 1))
        (c (svref *sha2-magic-number-array* 2))
        (d (svref *sha2-magic-number-array* 3))
        (e (svref *sha2-magic-number-array* 4))
        (f (svref *sha2-magic-number-array* 5))
        (g (svref *sha2-magic-number-array* 6))
        (h (svref *sha2-magic-number-array* 7))
        (a8 (convert-string-to-byte str :encoding encoding)))
    (subseq (apply #'concatenate 'string (loop for nothing from 0 below 7
                                            for i being the elements of (base-text a8 a b c d e f g h)
                                            collect (format nil "~16,'0x" i))) 0 96)))

(defun file (name)
  "sha384sum file"
  (let ((a (svref *sha2-magic-number-array* 0))
        (b (svref *sha2-magic-number-array* 1))
        (c (svref *sha2-magic-number-array* 2))
        (d (svref *sha2-magic-number-array* 3))
        (e (svref *sha2-magic-number-array* 4))
        (f (svref *sha2-magic-number-array* 5))
        (g (svref *sha2-magic-number-array* 6))
        (h (svref *sha2-magic-number-array* 7)))
    (subseq (apply #'concatenate 'string (loop for nothing from 0 below 7
                                            for i being the elements of (base-file name a b c d e f g h)
                                            collect (format nil "~16,'0x" i))) 0 96)))
