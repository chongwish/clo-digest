;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA256 Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://en.wikipedia.org/wiki/SHA-2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha2.256
  (:use :cl)
  (:nicknames :clo-digest-sha2-256)
  (:import-from #:clo-digest.sha2.32bit
                #:base-text
                #:base-file)
  (:import-from #:clo-digest.base
                #:convert-string-to-byte)
  (:export #:text
           #:file))

(in-package #:clo-digest.sha2.256)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *sha2-magic-number-array* '#(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))

(defun text (str &key (encoding :utf8))
  "sha256sum string"
  (let ((a (svref *sha2-magic-number-array* 0))
        (b (svref *sha2-magic-number-array* 1))
        (c (svref *sha2-magic-number-array* 2))
        (d (svref *sha2-magic-number-array* 3))
        (e (svref *sha2-magic-number-array* 4))
        (f (svref *sha2-magic-number-array* 5))
        (g (svref *sha2-magic-number-array* 6))
        (h (svref *sha2-magic-number-array* 7))
        (a8 (convert-string-to-byte str :encoding encoding)))
    (apply #'concatenate 'string (loop for i being the elements of (base-text a8 a b c d e f g h)
                                    collect (format nil "~8,'0x" i)))))

(defun file (name)
  "sha256sum file"
  (let ((a (svref *sha2-magic-number-array* 0))
        (b (svref *sha2-magic-number-array* 1))
        (c (svref *sha2-magic-number-array* 2))
        (d (svref *sha2-magic-number-array* 3))
        (e (svref *sha2-magic-number-array* 4))
        (f (svref *sha2-magic-number-array* 5))
        (g (svref *sha2-magic-number-array* 6))
        (h (svref *sha2-magic-number-array* 7)))
    (apply #'concatenate 'string (loop for i being the elements of (base-file name a b c d e f g h)
                                    collect (format nil "~8,'0x" i)))))
