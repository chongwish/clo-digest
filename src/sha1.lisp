;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA1 Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://tools.ietf.org/html/rfc3174
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha1
  (:use :cl)
  (:nicknames :clo-digest-sha1)
  (:import-from #:clo-operator.bit
                #:[64]=
                #:[32]=
                #:[32]and
                #:[32]or
                #:[32]not
                #:[32]xor
                #:[32]+
                #:[32]<<>
                #:[8]split)
  (:import-from #:clo-operator.endian
                #:transform)
  (:import-from #:clo-digest.base
                #:*block*
                #:calc-padding-64
                #:convert-to-32bit-be-array
                #:convert-string-to-byte)
  (:export #:text
           #:file))

(in-package #:clo-digest.sha1)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *sha1-magic-number-array* '#(#x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0))
  (defparameter *k-array* '#(#x5A827999 #x6ED9EBA1 #x8F1BBCDC #xCA62C1D6)))

(defmacro f1 (b c d)
  `([32]or ([32]and ,b ,c) ([32]and ([32]not ,b) ,d)))

(defmacro f2 (b c d)
  `([32]xor ,b ,c ,d))

(defmacro f3 (b c d)
  `([32]or ([32]and ,b ,c) ([32]and ,b ,d) ([32]and ,c ,d)))

(defmacro f4 (b c d)
  `([32]xor ,b ,c ,d))


(defmacro hash (a32bit pa pb pc pd pe)
  (let ((a (gensym)) (b (gensym)) (c (gensym)) (d (gensym)) (e (gensym)) (tmp (gensym)))
    `(let ((,a ,pa) (,b ,pb) (,c ,pc) (,d ,pd) (,e ,pe) (,tmp 0))
       (declare (type (unsigned-byte 32) ,a ,b ,c ,d ,e ,tmp))
       ,@(loop for i from 16 below 80
            collect `(setf (aref ,a32bit ,i) ([32]= ([32]<<> ([32]xor (aref ,a32bit ,(- i 3))
                                                               (aref ,a32bit ,(- i 8))
                                                               (aref ,a32bit ,(- i 14))
                                                               (aref ,a32bit ,(- i 16))) 1))))
       ,@(let ((op nil)
               (fn '#(f1 f2 f3 f4)))
           (dotimes (i 4)
             (dotimes (j 20)
               (setf op (nconc op `((setf ,tmp ([32]+ ([32]<<> ,a 5) (,(svref fn i) ,b ,c ,d) ,e (aref ,a32bit ,(+ (* i 20) j)) ,(svref *k-array* i))
                                          ,e ,d
                                          ,d ,c
                                          ,c ([32]<<> ,b 30)
                                          ,b ,a
                                          ,a ,tmp))))))
           op)
       (setf ,a ([32]+ ,a ,pa)
             ,b ([32]+ ,b ,pb)
             ,c ([32]+ ,c ,pc)
             ,d ([32]+ ,d ,pd)
             ,e ([32]+ ,e ,pe))
       (vector ,a ,b ,c ,d ,e))))


(defun text (str &key (encoding :utf-8))
  "sha1sum string"
  (let ((a (svref *sha1-magic-number-array* 0))
        (b (svref *sha1-magic-number-array* 1))
        (c (svref *sha1-magic-number-array* 2))
        (d (svref *sha1-magic-number-array* 3))
        (e (svref *sha1-magic-number-array* 4))
        (a8 (convert-string-to-byte str :encoding encoding)))
    (let* ((len8 (length a8))
           (len (+ len8 8 (calc-padding-64 len8)))
           (a32 (make-array (/ len 4) :element-type '(unsigned-byte 32))))
      (convert-to-32bit-be-array a32 a8 len8 len8)
      (loop for i from 0 below (/ (/ len 4) 16)
         do (let ((a32b80 (make-array 80 :element-type '(unsigned-byte 32)))
                  (sub-a32 (subseq a32 (* i 16) (+ (* i 16) 16))))
              (loop for i from 0 below 16 do (setf (aref a32b80 i) (aref sub-a32 i)))
              (let ((v (hash a32b80 a b c d e)))
                (setf a (aref v 0)
                      b (aref v 1)
                      c (aref v 2)
                      d (aref v 3)
                      e (aref v 4)))))
      (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d ,e)
                                      collect (format nil "~8,'0x" i))))))


(defun file (name)
  "sha1sum file"  
  (let ((a (svref *sha1-magic-number-array* 0))
        (b (svref *sha1-magic-number-array* 1))
        (c (svref *sha1-magic-number-array* 2))
        (d (svref *sha1-magic-number-array* 3))
        (e (svref *sha1-magic-number-array* 4))
        (count 0)
        (a32b80 (make-array 80 :element-type '(unsigned-byte 32)))
        (a8 (make-array (* 64 *block*) :element-type '(unsigned-byte 8))))
    (with-open-file (in name :direction :input :element-type '(unsigned-byte 8))
      (let ((bi (read-sequence a8 in)))
        (do* ((bi-prev bi bi)
              (a8-prev (copy-seq a8) (copy-seq a8))
              (bi (read-sequence a8 in) (read-sequence a8 in)))
             ((= bi-prev 0) (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d ,e)
                                                            collect (format nil "~8,'0x" i))))
          (let ((a32 (make-array (if (= bi 0) (/ (+ bi-prev 8 (calc-padding-64 bi-prev)) 4) (/ bi-prev 4)) :element-type '(unsigned-byte 32))))
            (setf count (+ count bi-prev))
            (convert-to-32bit-be-array a32 a8-prev bi-prev (if (= bi 0) count))
            (loop for i from 0 below (/ (length a32) 16)
               do (let ((sub-a32 (subseq a32 (* i 16) (+ (* i 16) 16))))
                    (loop for i from 0 below 16 do (setf (aref a32b80 i) (aref sub-a32 i)))
                    (let ((v (hash a32b80 a b c d e)))
                      (setf a (aref v 0)
                            b (aref v 1)
                            c (aref v 2)
                            d (aref v 3)
                            e (aref v 4)))))))))))
