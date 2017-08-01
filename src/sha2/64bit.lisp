;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA512 AND SHA384 Base Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://en.wikipedia.org/wiki/SHA-2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha2.64bit
  (:use :cl)
  (:nicknames :clo-digest-sha2-64bit)
  (:import-from #:clo-operator.bit
                #:[64]=
                #:[64]and
                #:[64]or
                #:[64]not
                #:[64]xor
                #:[64]+
                #:[64]<>>
                #:[64]>>)
  (:import-from #:clo-operator.endian
                #:transform)
  (:import-from #:clo-digest.base
                #:*block*
                #:calc-padding-128
                #:convert-to-64bit-be-array
                #:convert-string-to-byte)
  (:export #:base-text
           #:base-file))

(in-package #:clo-digest.sha2.64bit)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *k-array*
    '#(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc #x3956c25bf348b538
       #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118 #xd807aa98a3030242 #x12835b0145706fbe
       #x243185be4ee4b28c #x550c7dc3d5ffb4e2 #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235
       #xc19bf174cf692694 #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
       #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5 #x983e5152ee66dfab
       #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4 #xc6e00bf33da88fc2 #xd5a79147930aa725
       #x06ca6351e003826f #x142929670a0e6e70 #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed
       #x53380d139d95b3df #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b 
       #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30 #xd192e819d6ef5218
       #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8 #x19a4c116b8d2d0c8 #x1e376c085141ab53
       #x2748774cdf8eeb99 #x34b0bcb5e19b48a8 #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373
       #x682e6ff3d6b2b8a3 #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
       #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b #xca273eceea26619c
       #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178 #x06f067aa72176fba #x0a637dc5a2c898a6
       #x113f9804bef90dae #x1b710b35131c471b #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc
       #x431d67c49c100d4c #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817)))


(defmacro hash (a64bit pa pb pc pd pe pf pg ph)
  (let ((a (gensym)) (b (gensym)) (c (gensym)) (d (gensym)) (e (gensym)) (f (gensym)) (g (gensym)) (h (gensym)) (wi15 (gensym)) (wi2 (gensym)) (temp1 (gensym)) (temp2 (gensym)))
    `(let ((,a ,pa) (,b ,pb) (,c ,pc) (,d ,pd) (,e ,pe) (,f ,pf) (,g ,pg) (,h ,ph) (,temp1 0) (,temp2 0))
       (declare (type (unsigned-byte 64) ,a ,b ,c ,d ,e ,f ,g ,h ,temp1 ,temp2))
       ,@(loop for i from 16 below 80
            collect `(let ((,wi15 (aref ,a64bit ,(- i 15)))
                           (,wi2 (aref ,a64bit ,(- i 2))))
                       (setf (aref ,a64bit ,i) ([64]+ (aref ,a64bit ,(- i 16))
                                                      (logxor ([64]<>> ,wi15 1) ([64]<>> ,wi15 8) (ash ,wi15 -7))
                                                      (aref ,a64bit ,(- i 7))
                                                      (logxor ([64]<>> ,wi2 19) ([64]<>> ,wi2 61) (ash ,wi2 -6))))))
       ,@(let ((op nil))
           (dotimes (i 80)
             (setf op (nconc op `((setf ,temp1 ([64]+ ,h
                                                      (logxor ([64]<>> ,e 14) ([64]<>> ,e 18) ([64]<>> ,e 41))
                                                      (logxor (logand ,e ,f) (logand (lognot ,e) ,g))
                                                      ,(svref *k-array* i)
                                                      (aref ,a64bit ,i))
                                        ,temp2 ([64]+ (logxor ([64]<>> ,a 28) ([64]<>> ,a 34) ([64]<>> ,a 39))
                                                      (logxor (logand ,a ,b) (logand ,a ,c) (logand ,b ,c)))
                                        ,h ,g
                                        ,g ,f
                                        ,f ,e
                                        ,e ([64]+ ,d ,temp1)
                                        ,d ,c
                                        ,c ,b
                                        ,b ,a
                                        ,a ([64]+ ,temp1 ,temp2)
                                        )))))
           op)
       (setf ,a ([64]+ ,a ,pa)
             ,b ([64]+ ,b ,pb)
             ,c ([64]+ ,c ,pc)
             ,d ([64]+ ,d ,pd)
             ,e ([64]+ ,e ,pe)
             ,f ([64]+ ,f ,pf)
             ,g ([64]+ ,g ,pg)
             ,h ([64]+ ,h ,ph))
       (vector ,a ,b ,c ,d ,e ,f ,g ,h))))


(defun base-text (a8 a b c d e f g h)
  "sha384sum and sha512sum string"
  (let* (v
         (len8 (length a8))
         (len (+ len8 16 (calc-padding-128 len8)))
         (a64 (make-array (/ len 8) :element-type '(unsigned-byte 64))))
    (convert-to-64bit-be-array a64 a8 len8 len8)
    (loop for i from 0 below (/ (/ len 8) 16)
       do (let ((a64b80 (make-array 80 :element-type '(unsigned-byte 64)))
                (sub-a64 (subseq a64 (* i 16) (+ (* i 16) 16))))
            (loop for i from 0 below 16 do (setf (aref a64b80 i) (aref sub-a64 i)))
            (setf v (hash a64b80 a b c d e f g h)
                  a (aref v 0)
                  b (aref v 1)
                  c (aref v 2)
                  d (aref v 3)
                  e (aref v 4)
                  f (aref v 5)
                  g (aref v 6)
                  h (aref v 7))))
    v))


(defun base-file (name a b c d e f g h)
  "sha384sum and sha512sum file"
  (let (v
        (count 0)
        (a64b80 (make-array 80 :element-type '(unsigned-byte 64)))
        (a8 (make-array (* 64 *block*) :element-type '(unsigned-byte 8))))
    (with-open-file (in name :direction :input :element-type '(unsigned-byte 8))
      (let ((bi (read-sequence a8 in)))
        (do* ((bi-prev bi bi)
              (a8-prev (copy-seq a8) (copy-seq a8))
              (bi (read-sequence a8 in) (read-sequence a8 in)))
             ((= bi-prev 0) v)
          (let ((a64 (make-array (if (= bi 0) (/ (+ bi-prev 16 (calc-padding-128 bi-prev)) 8) (/ bi-prev 8)) :element-type '(unsigned-byte 64))))
            (setf count (+ count bi-prev))
            (convert-to-64bit-be-array a64 a8-prev bi-prev (if (= bi 0) count))
            (loop for i from 0 below (/ (length a64) 16)
               do (let ((sub-a64 (subseq a64 (* i 16) (+ (* i 16) 16))))
                    (loop for i from 0 below 16 do (setf (aref a64b80 i) (aref sub-a64 i)))
                    (setf v (hash a64b80 a b c d e f g h)
                          a (aref v 0)
                          b (aref v 1)
                          c (aref v 2)
                          d (aref v 3)
                          e (aref v 4)
                          f (aref v 5)
                          g (aref v 6)
                          h (aref v 7))))))))))
