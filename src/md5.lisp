;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp MD5 Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;
;;; documentation: https://www.ietf.org/rfc/rfc1321.txt
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.md5
  (:use :cl)
  (:import-from #:clo-operator.bit
                #:[64]=
                #:[32]=
                #:[32]<<
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
                #:convert-to-32bit-le-array
                #:convert-string-to-byte)
  (:nicknames :clo-coding-md5)
  (:export #:stream
           #:text
           #:file))

(in-package #:clo-digest.md5)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *md5-magic-number-list* '#(#x67452301 #xEFCDAB89 #x98BADCFE #x10325476))
  (defparameter *md5-ac-list*
    (let ((l (make-array 64 :fill-pointer 0 :element-type '(unsigned-byte 32))))
      (dotimes (i 64)
        (vector-push (floor (* #x100000000 (abs (sin (+ 1d0 i))))) l))
      l))
  (defparameter *md5-shift-list* '#(7 12 17 22 5 9 14 20 4 11 16 23 6 10 15 21))
  (defparameter *md5-x-list*
    '#(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
       1 6 11 0 5 10 15 4 9 14 3 8 13 2 7 12
       5 8 11 14 1 4 7 10 13 0 3 6 9 12 15 2
       0 7 14 5 12 3 10 1 8 15 6 13 4 11 2 9)))

(defmacro F (x y z)
  `([32]or ([32]and ,x ,y) ([32]and ([32]not ,x) ,z)))

(defmacro G (x y z)
  `([32]or ([32]and ,x ,z) ([32]and ,y ([32]not ,z))))

(defmacro H (x y z)
  `([32]xor ,x ,y ,z))

(defmacro I (x y z)
  `([32]xor ,y ([32]or ,x ([32]not ,z))))

(defmacro __(fn a b c d x s ac)
  `([32]+ ,b ([32]<<> ([32]+ ,a (,fn ,b ,c ,d) ,x ,ac) ,s)))

(defmacro FF (a b c d x s ac)
  `(__ F ,a ,b ,c ,d ,x ,s ,ac))

(defmacro GG (a b c d x s ac)
  `(__ G ,a ,b ,c ,d ,x ,s ,ac))

(defmacro HH (a b c d x s ac)
  `(__ H ,a ,b ,c ,d ,x ,s ,ac))

(defmacro II (a b c d x s ac)
  `(__ I ,a ,b ,c ,d ,x ,s ,ac))


(defmacro hash (l pa pb pc pd)
  "hash a 32-bit list which length is 16 to 4 number"
  (let ((a (gensym)) (b (gensym)) (c (gensym)) (d (gensym)))
    `(let ((,a ,pa) (,b ,pb) (,c ,pc) (,d ,pd))
       (declare (type (unsigned-byte 32) ,a ,b ,c ,d))
       ,@(let ((op nil)
               (fn '#(FF GG HH II)))
           (dotimes (i 4)
             (dotimes (j 4)
               (let ((i16 (* i 16))
                     (i4 (* i 4))
                     (j4 (* j 4)))
                 (setf op (nconc op `((setf ,a (,(svref fn i) ,a ,b ,c ,d (aref ,l ,(svref *md5-x-list* (+ i16 j4 0))) ,(svref *md5-shift-list* (+ i4 0)) ,(aref *md5-ac-list* (+ i16 j4 0))))
                                      (setf ,d (,(svref fn i) ,d ,a ,b ,c (aref ,l ,(svref *md5-x-list* (+ i16 j4 1))) ,(svref *md5-shift-list* (+ i4 1)) ,(aref *md5-ac-list* (+ i16 j4 1))))
                                      (setf ,c (,(svref fn i) ,c ,d ,a ,b (aref ,l ,(svref *md5-x-list* (+ i16 j4 2))) ,(svref *md5-shift-list* (+ i4 2)) ,(aref *md5-ac-list* (+ i16 j4 2))))
                                      (setf ,b (,(svref fn i) ,b ,c ,d ,a (aref ,l ,(svref *md5-x-list* (+ i16 j4 3))) ,(svref *md5-shift-list* (+ i4 3)) ,(aref *md5-ac-list* (+ i16 j4 3))))))))))
           op)
       (setf ,a ([32]+ ,a ,pa)
             ,b ([32]+ ,b ,pb)
             ,c ([32]+ ,c ,pc)
             ,d ([32]+ ,d ,pd))
       (vector ,a ,b ,c ,d))))


(defun text (str &key (encoding :utf-8))
  "md5sum string"
  (let ((a (svref *md5-magic-number-list* 0))
        (b (svref *md5-magic-number-list* 1))
        (c (svref *md5-magic-number-list* 2))
        (d (svref *md5-magic-number-list* 3))
        (a8 (convert-string-to-byte str :encoding encoding)))
    (let* ((len8 (length a8))
           (len (+ len8 8 (calc-padding-64 len8)))
           (a32 (make-array (/ len 4) :element-type '(unsigned-byte 32))))
      (convert-to-32bit-le-array a32 a8 len8 len8)
      (loop for i from 0 below (/ (/ len 4) 16)
         do (let ((v (hash (subseq a32 (* i 16) (+ (* i 16) 16)) a b c d)))
              (setf a (aref v 0)
                    b (aref v 1)
                    c (aref v 2)
                    d (aref v 3))))
      (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d)
                                      collect (format nil "~8,'0x" (transform i)))))))


(defun file (name)
  "md5sum file"
  (let ((a (svref *md5-magic-number-list* 0))
        (b (svref *md5-magic-number-list* 1))
        (c (svref *md5-magic-number-list* 2))
        (d (svref *md5-magic-number-list* 3))
        (count 0)
        (a8 (make-array (* 64 *block*) :element-type '(unsigned-byte 8))))
    (with-open-file (in name :direction :input :element-type '(unsigned-byte 8))
      (let ((bi (read-sequence a8 in)))
        (do* ((bi-prev bi bi)
              (a8-prev (copy-seq a8) (copy-seq a8))
              (bi (read-sequence a8 in) (read-sequence a8 in)))
             ((= bi-prev 0) (apply #'concatenate 'string (loop for i in `(,a ,b ,c ,d)
                                                            collect (format nil "~8,'0x" (transform i)))))
          (let ((a32 (make-array (if (= bi-prev (* 64 *block*)) (/ bi-prev 4) (/ (+ bi-prev 8 (calc-padding-64 bi-prev)) 4)) :element-type '(unsigned-byte 32))))
            (setf count (+ count bi-prev))
            (convert-to-32bit-le-array a32 a8-prev bi-prev (if (< bi-prev (* 64 *block*)) count))
            (loop for i from 0 below (/ (length a32) 16)
               do (let* ((i16 (* i 16))
                         (sub-a32 (subseq a32 i16 (+ i16 16)))
                         (v (hash sub-a32 a b c d)))
                    (setf a (aref v 0)
                          b (aref v 1)
                          c (aref v 2)
                          d (aref v 3))))))))))
