;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA256 Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://en.wikipedia.org/wiki/SHA-2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha2.512
  (:use :cl)
  (:nicknames :clo-digest-sha2-512)
  (:import-from #:clo-digest.sha2.64bit
                #:base-text
                #:base-file)
  (:import-from #:clo-digest.base
                #:convert-string-to-byte)
  (:export #:text
           #:file))

(in-package #:clo-digest.sha2.512)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *sha2-magic-number-array* '#(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f #x1f83d9abfb41bd6b #x5be0cd19137e2179)))

(defun text (str &key (encoding :utf8))
  "sha512sum string"
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
                                    collect (format nil "~16,'0x" i)))))


(defun file (name)
  "sha512sum file"
  (let ((a (svref *sha2-magic-number-array* 0))
        (b (svref *sha2-magic-number-array* 1))
        (c (svref *sha2-magic-number-array* 2))
        (d (svref *sha2-magic-number-array* 3))
        (e (svref *sha2-magic-number-array* 4))
        (f (svref *sha2-magic-number-array* 5))
        (g (svref *sha2-magic-number-array* 6))
        (h (svref *sha2-magic-number-array* 7)))
    (apply #'concatenate 'string (loop for i being the elements of (base-file name a b c d e f g h)
                                    collect (format nil "~16,'0x" i)))))
