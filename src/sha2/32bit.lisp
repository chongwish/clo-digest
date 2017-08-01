;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp SHA256 AND SHA224 Base Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://en.wikipedia.org/wiki/SHA-2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.sha2.32bit
  (:use :cl)
  (:nicknames :clo-digest-sha2-32bit)
  (:import-from #:clo-operator.bit
                #:[64]=
                #:[32]=
                #:[32]and
                #:[32]or
                #:[32]not
                #:[32]xor
                #:[32]+
                #:[32]<>>
                #:[32]>>)
  (:import-from #:clo-operator.endian
                #:transform)
  (:import-from #:clo-digest.base
                #:*block*
                #:calc-padding-64
                #:convert-to-32bit-be-array
                #:convert-string-to-byte)
  (:export #:base-text
           #:base-file))

(in-package #:clo-digest.sha2.32bit)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)  
  (defparameter *k-array*
    '#(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
       #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
       #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
       #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
       #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
       #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
       #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
       #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))


(defmacro hash (a32bit pa pb pc pd pe pf pg ph)
  (let ((a (gensym)) (b (gensym)) (c (gensym)) (d (gensym)) (e (gensym)) (f (gensym)) (g (gensym)) (h (gensym)) (wi15 (gensym)) (wi2 (gensym)) (temp1 (gensym)) (temp2 (gensym)))
    `(let ((,a ,pa) (,b ,pb) (,c ,pc) (,d ,pd) (,e ,pe) (,f ,pf) (,g ,pg) (,h ,ph) (,temp1 0) (,temp2 0))
       (declare (type (unsigned-byte 32) ,a ,b ,c ,d ,e ,f ,g ,h ,temp1 ,temp2))
       ,@(loop for i from 16 below 64
            collect `(let ((,wi15 (aref ,a32bit ,(- i 15)))
                           (,wi2 (aref ,a32bit ,(- i 2))))
                       (setf (aref ,a32bit ,i) ([32]+ (aref ,a32bit ,(- i 16))
                                                      (logxor ([32]<>> ,wi15 7) ([32]<>> ,wi15 18) (ash ,wi15 -3))
                                                      (aref ,a32bit ,(- i 7))
                                                      (logxor ([32]<>> ,wi2 17) ([32]<>> ,wi2 19) (ash ,wi2 -10))))))
       ,@(let ((op nil))
           (dotimes (i 64)
             (setf op (nconc op `((setf ,temp1 ([32]+ ,h
                                                      (logxor ([32]<>> ,e 6) ([32]<>> ,e 11) ([32]<>> ,e 25))
                                                      (logxor (logand ,e ,f) (logand (lognot ,e) ,g))
                                                      ,(svref *k-array* i)
                                                      (aref ,a32bit ,i))
                                        ,temp2 ([32]+ (logxor ([32]<>> ,a 2) ([32]<>> ,a 13) ([32]<>> ,a 22))
                                                      (logxor (logand ,a ,b) (logand ,a ,c) (logand ,b ,c)))
                                        ,h ,g
                                        ,g ,f
                                        ,f ,e
                                        ,e ([32]+ ,d ,temp1)
                                        ,d ,c
                                        ,c ,b
                                        ,b ,a
                                        ,a ([32]+ ,temp1 ,temp2))))))
           op)
       (setf ,a ([32]+ ,a ,pa)
             ,b ([32]+ ,b ,pb)
             ,c ([32]+ ,c ,pc)
             ,d ([32]+ ,d ,pd)
             ,e ([32]+ ,e ,pe)
             ,f ([32]+ ,f ,pf)
             ,g ([32]+ ,g ,pg)
             ,h ([32]+ ,h ,ph))
       (vector ,a ,b ,c ,d ,e ,f ,g ,h))))


(defun base-text (a8 a b c d e f g h)
  "sha224sum and sha256sum string"
  (let* (v
         (len8 (length a8))
         (len (+ len8 8 (calc-padding-64 len8)))
         (a32 (make-array (/ len 4) :element-type '(unsigned-byte 32))))
    (convert-to-32bit-be-array a32 a8 len8 len8)
    (loop for i from 0 below (/ (/ len 4) 16)
       do (let ((a32b64 (make-array 64 :element-type '(unsigned-byte 32)))
                (sub-a32 (subseq a32 (* i 16) (+ (* i 16) 16))))
            (loop for i from 0 below 16 do (setf (aref a32b64 i) (aref sub-a32 i)))
            (setf v (hash a32b64 a b c d e f g h)
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
  "sha224 and sha256sum file"
  (let (v
        (count 0)
        (a32b64 (make-array 64 :element-type '(unsigned-byte 32)))
        (a8 (make-array (* 64 *block*) :element-type '(unsigned-byte 8))))
    (with-open-file (in name :direction :input :element-type '(unsigned-byte 8))
      (let ((bi (read-sequence a8 in)))
        (do* ((bi-prev bi bi)
              (a8-prev (copy-seq a8) (copy-seq a8))
              (bi (read-sequence a8 in) (read-sequence a8 in)))
             ((= bi-prev 0) v)
          (let ((a32 (make-array (if (= bi 0) (/ (+ bi-prev 8 (calc-padding-64 bi-prev)) 4) (/ bi-prev 4)) :element-type '(unsigned-byte 32))))
            (setf count (+ count bi-prev))
            (convert-to-32bit-be-array a32 a8-prev bi-prev (if (= bi 0) count))
            (loop for i from 0 below (/ (length a32) 16)
               do (let ((sub-a32 (subseq a32 (* i 16) (+ (* i 16) 16))))
                    (loop for i from 0 below 16 do (setf (aref a32b64 i) (aref sub-a32 i)))
                    (setf v (hash a32b64 a b c d e f g h)
                          a (aref v 0)
                          b (aref v 1)
                          c (aref v 2)
                          d (aref v 3)
                          e (aref v 4)
                          f (aref v 5)
                          g (aref v 6)
                          h (aref v 7))))))))))
