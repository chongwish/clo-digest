;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp Blake2b Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://blake2.net
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.blake2b
  (:use :cl)
  (:nicknames :clo-digest-blake2b)
  (:import-from #:clo-operator.bit
                #:[64]=
                #:[64]and
                #:[64]or
                #:[64]not
                #:[64]xor
                #:[64]+
                #:[64]<>>
                #:[64]<<
                #:[64]>>)
  (:import-from #:clo-operator.endian
                #:transform)
  (:import-from #:clo-digest.base
                #:*block*
                #:pad
                #:calc-padding-128
                #:convert-to-64bit-be-array
                #:convert-to-64bit-le-array
                #:convert-string-to-byte)
  (:export #:text
           #:file))

(in-package #:clo-digest.blake2b)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *sigma* '#(#(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
                           #(14 10 4 8 9 15 13 6 1 12 0 2 11 7 5 3)
                           #(11 8 12 0 5 2 15 13 10 14 3 6 7 1 9 4)
                           #(7 9 3 1 13 12 11 14 2 6 5 10 4 0 15 8)
                           #(9 0 5 7 2 4 10 15 14 1 11 12 6 8 3 13)
                           #(2 12 6 10 0 11 8 3 4 13 7 5 15 14 1 9)
                           #(12 5 1 15 14 13 4 10 0 7 6 3 9 2 8 11)
                           #(13 11 7 14 12 1 3 9 5 0 15 4 8 6 2 10)
                           #(6 15 14 9 11 3 0 8 12 2 13 7 1 4 10 5)
                           #(10 2 8 4 7 6 1 5 15 11 9 14 3 12 13 0)
                           #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
                           #(14 10 4 8 9 15 13 6 1 12 0 2 11 7 5 3)))
  (defparameter *blake2b-magic-number-array* '#(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f #x1f83d9abfb41bd6b #x5be0cd19137e2179)))


(defmacro mix (a b c d x y)
  `(setf ,a ([64]+ ,a ,b ,x)
         ,d ([64]<>> ([64]xor ,d ,a) 32)
         ,c ([64]+ ,c ,d)
         ,b ([64]<>> ([64]xor ,b ,c) 24)
         ,a ([64]+ ,a ,b ,y)
         ,d ([64]<>> ([64]xor ,d ,a) 16)
         ,c ([64]+ ,c ,d)
         ,b ([64]<>> ([64]xor ,b ,c) 63)))

(defmacro hash (a64bit pa pb pc pd pe pf pg ph count last)
  (let ((a (gensym)) (a2 (gensym))
        (b (gensym)) (b2 (gensym))
        (c (gensym)) (c2 (gensym))
        (d (gensym)) (d2 (gensym))
        (e (gensym)) (e2 (gensym))
        (f (gensym)) (f2 (gensym))
        (g (gensym)) (g2 (gensym))
        (h (gensym)) (h2 (gensym)))
    `(let ((,a ,pa) (,b ,pb) (,c ,pc) (,d ,pd) (,e ,pe) (,f ,pf) (,g ,pg) (,h ,ph)
           (,a2 ,(svref *blake2b-magic-number-array* 0))
           (,b2 ,(svref *blake2b-magic-number-array* 1))
           (,c2 ,(svref *blake2b-magic-number-array* 2))
           (,d2 ,(svref *blake2b-magic-number-array* 3))
           (,e2 ([64]xor ,(svref *blake2b-magic-number-array* 4) (ldb (byte 64 0) ,count)))
           (,f2 ([64]xor ,(svref *blake2b-magic-number-array* 5) (ldb (byte 64 64) ,count)))
           (,g2 (if ,last ,([64]not (svref *blake2b-magic-number-array* 6)) ,(svref *blake2b-magic-number-array* 6)))
           (,h2 ,(svref *blake2b-magic-number-array* 7)))
       (declare (type (unsigned-byte 64) ,a ,b ,c ,d ,e ,f ,g ,h ,a2 ,b2 ,c2 ,d2 ,e2 ,f2 ,g2 ,h2))
       ,@(let ((op nil))
           (dotimes (i 12)
             (setf op (nconc op `((mix ,a ,e ,a2 ,e2 (aref ,a64bit ,(svref (svref *sigma* i) 0)) (aref ,a64bit ,(svref (svref *sigma* i) 1)))
                                  (mix ,b ,f ,b2 ,f2 (aref ,a64bit ,(svref (svref *sigma* i) 2)) (aref ,a64bit ,(svref (svref *sigma* i) 3)))
                                  (mix ,c ,g ,c2 ,g2 (aref ,a64bit ,(svref (svref *sigma* i) 4)) (aref ,a64bit ,(svref (svref *sigma* i) 5)))
                                  (mix ,d ,h ,d2 ,h2 (aref ,a64bit ,(svref (svref *sigma* i) 6)) (aref ,a64bit ,(svref (svref *sigma* i) 7)))
                                  (mix ,a ,f ,c2 ,h2 (aref ,a64bit ,(svref (svref *sigma* i) 8)) (aref ,a64bit ,(svref (svref *sigma* i) 9)))
                                  (mix ,b ,g ,d2 ,e2 (aref ,a64bit ,(svref (svref *sigma* i) 10)) (aref ,a64bit ,(svref (svref *sigma* i) 11)))
                                  (mix ,c ,h ,a2 ,f2 (aref ,a64bit ,(svref (svref *sigma* i) 12)) (aref ,a64bit ,(svref (svref *sigma* i) 13)))
                                  (mix ,d ,e ,b2 ,g2 (aref ,a64bit ,(svref (svref *sigma* i) 14)) (aref ,a64bit ,(svref (svref *sigma* i) 15)))))))
           op)
       (setf ,a ([64]xor ,pa ,a2 ,a)
             ,b ([64]xor ,pb ,b2 ,b)
             ,c ([64]xor ,pc ,c2 ,c)
             ,d ([64]xor ,pd ,d2 ,d)
             ,e ([64]xor ,pe ,e2 ,e)
             ,f ([64]xor ,pf ,f2 ,f)
             ,g ([64]xor ,pg ,g2 ,g)
             ,h ([64]xor ,ph ,h2 ,h))
       (vector ,a ,b ,c ,d ,e ,f ,g ,h))))


(defun text (str &key (seed "") (outlen 64) (encoding :utf8))
  "blake2bsum string"
  (let (a
        (b (svref *blake2b-magic-number-array* 1))
        (c (svref *blake2b-magic-number-array* 2))
        (d (svref *blake2b-magic-number-array* 3))
        (e (svref *blake2b-magic-number-array* 4))
        (f (svref *blake2b-magic-number-array* 5))
        (g (svref *blake2b-magic-number-array* 6))
        (h (svref *blake2b-magic-number-array* 7))
        (seed-len (length seed))
        (a8 (convert-string-to-byte str :encoding encoding)))
    (if (> seed-len 0) (setf seed (convert-string-to-byte seed :encoding encoding)
                             seed-len (length seed)
                             a8 (concatenate 'vector seed (pad #() (- 128 seed-len) 0) a8)))
    (setf a ([64]xor #x01010000 ([64]<< seed-len 8) outlen (svref *blake2b-magic-number-array* 0)))
    (let* ((a8-len (length a8))
           (a8-pad (if (= a8-len 0) 128 (rem (- 128 (rem a8-len 128)) 128)))
           (a8 (concatenate 'vector a8 (pad #() a8-pad 0)))
           v
           (last? nil)
           (len (/ (length a8) 8))
           (len/16 (/ len 16))
           (a64 (make-array len :element-type '(unsigned-byte 64))))
      (convert-to-64bit-le-array a64 a8)
      (loop for i from 0 below len/16
         do (let* ((i16-start (* i 16))
                   (i16-end (+ i16-start 16))
                   (count (* i16-end 8))
                   (sub-a64 (subseq a64 i16-start i16-end)))
              (if (>= count a8-len)
                  (setf last? t
                        count a8-len))
              (setf v (hash sub-a64 a b c d e f g h count last?)
                    a (aref v 0)
                    b (aref v 1)
                    c (aref v 2)
                    d (aref v 3)
                    e (aref v 4)
                    f (aref v 5)
                    g (aref v 6)
                    h (aref v 7)))))
    (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d ,e ,f ,g ,h)
                                    for j from 0 below (/ outlen 8)
                                    collect (format nil "~16,'0x" (transform i :bit 64))))))


(defun file (name &key (seed "") (outlen 64) (encoding :utf8))
  "blake2bsum file"
  (let ((b (svref *blake2b-magic-number-array* 1))
        (c (svref *blake2b-magic-number-array* 2))
        (d (svref *blake2b-magic-number-array* 3))
        (e (svref *blake2b-magic-number-array* 4))
        (f (svref *blake2b-magic-number-array* 5))
        (g (svref *blake2b-magic-number-array* 6))
        (h (svref *blake2b-magic-number-array* 7))
        (last? nil)
        (count 0)
        a a8 v
        (seed-len (length seed)))
    (if (> seed-len 0) (setf seed (convert-string-to-byte seed :encoding encoding)
                             seed-len (length seed)))
    (setf a ([64]xor #x01010000 ([64]<< seed-len 8) outlen (svref *blake2b-magic-number-array* 0)))
    (unless (<= seed-len 0)
      (setf a8 (concatenate 'vector seed (pad #() (- 128 seed-len) 0)))
      (setf count 128)
      (let ((a64 (make-array 16 :element-type '(unsigned-byte 64))))
        (convert-to-64bit-le-array a64 a8)
        (setf v (hash a64 a b c d e f g h count last?)
              a (aref v 0)
              b (aref v 1)
              c (aref v 2)
              d (aref v 3)
              e (aref v 4)
              f (aref v 5)
              g (aref v 6)
              h (aref v 7))))
    (setf a8 (make-array (* 64 *block*) :element-type '(unsigned-byte 8)))
    (with-open-file (in name :direction :input :element-type '(unsigned-byte 8))
      (let ((bi (read-sequence a8 in))
            (count-block count))
        (do* ((bi-prev bi bi)
              (a8-prev (copy-seq a8) (copy-seq a8))
              (bi (read-sequence a8 in) (read-sequence a8 in))
              (len bi-prev bi-prev))
             ((= bi-prev 0) (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d ,e ,f ,g ,h)
                                                            for j from 0 below (/ outlen 8)
                                                           collect (format nil "~16,'0x" (transform i :bit 64)))))
          (setf count-block (+ count-block bi-prev))
          (let* ((a8-pad (if (= bi 0) (if (= bi-prev 0)
                                          128
                                          (rem (- 128 (rem bi-prev 128)) 128)) 0))
                 (a64 (make-array (/ (+ a8-pad bi-prev) 8) :element-type '(unsigned-byte 64))))
            (unless (/= bi 0)
              (setf a8-prev (concatenate 'vector (subseq a8-prev 0 bi-prev) (pad #() a8-pad 0)))
              (setf len (+ len a8-pad)))
            (convert-to-64bit-le-array a64 a8-prev)
            (loop for i from 0 below (/ len 128)
               do (let* ((i16-start (* i 16))
                         (i16-end (+ i16-start 16))
                         (sub-a64 (subseq a64 i16-start i16-end)))
                    (setf count (+ count 128))
                    (if (and (= bi 0) (>= count count-block))
                        (setf last? t
                              count count-block))
                    (setf v (hash sub-a64 a b c d e f g h count last?)
                          a (aref v 0)
                          b (aref v 1)
                          c (aref v 2)
                          d (aref v 3)
                          e (aref v 4)
                          f (aref v 5)
                          g (aref v 6)
                          h (aref v 7))))))))))


