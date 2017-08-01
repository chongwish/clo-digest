;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Common Lisp Digest Library
;;; @author: chongwish
;;; @email: chongwish@gmail.com
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage #:clo-digest.base
  (:use :cl)
  (:import-from #:clo-operator.bit
                #:[8]split)
  (:nicknames :clo-digest-base)
  (:export #:*block*
           #:calc-padding-64
           #:calc-padding-128
           #:pad
           #:merge-to-be-32bit
           #:merge-to-be-64bit
           #:merge-to-le-32bit
           #:merge-to-le-64bit
           #:expand-64bit-to-be-vector
           #:expand-128bit-to-be-vector
           #:expand-64bit-to-le-vector
           #:expand-128bit-to-le-vector
           #:convert-to-32bit-be-array
           #:convert-to-32bit-le-array
           #:convert-string-to-byte))

(clo-operator.bit:template 64)

(in-package #:clo-digest.base)

(declaim (optimize (speed 3) (safety 0) (space 0) (debug 0)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *block* 1024))


(declaim (inline calc-padding-64))
(defun calc-padding-64 (n)
  "calc a number that can be divided evenly by 64 when it add 56 and it must be less than 64"
  (let ((result (- 56 (rem n 64))))
    (if (plusp result)
        result
        (+ 64 result))))


(declaim (inline calc-padding-128))
(defun calc-padding-128 (n)
  "calc a number that can be divided evenly by 128 when it add 112 and it must be less than 64"
  (let ((result (- 112 (rem n 128))))
    (if (plusp result)
        result
        (+ 128 result))))


(declaim (inline pad))
(defun pad (a n &optional (b #b10000000))
  "pad n 8-bit number and the first is #b10000000 to array a"
  (let ((temp (make-array n :fill-pointer 0 :element-type '(unsigned-byte 8))))
    (vector-push b temp)
    (loop for i from 1 below n do (vector-push 0 temp))
    (concatenate 'vector a temp)))


(defmacro merge-to-le-32bit (a32bit i a8bit j)
  "merge 4 number in a 8bit array to 1 number in a 32bit array"
  (let ((result (gensym)))
    `(let ((,result 0))
       (setf (ldb (byte 8 0) ,result) (aref ,a8bit ,j)
             (ldb (byte 8 8) ,result) (aref ,a8bit (+ ,j 1))
             (ldb (byte 8 16) ,result) (aref ,a8bit (+ ,j 2))
             (ldb (byte 8 24) ,result) (aref ,a8bit (+ ,j 3))
             (aref ,a32bit ,i) ,result))))


(defmacro merge-to-le-64bit (a64bit i a8bit j)
  "merge 4 number in a 8bit array to 1 number in a 64bit array"
  (let ((result (gensym)))
    `(let ((,result 0))
       ,@(loop for i from 0 below 8
            collect `(setf (ldb (byte 8 ,(* 8 i)) ,result) (aref ,a8bit (+ ,j ,i))))
       (setf (aref ,a64bit ,i) ,result))))


(defmacro merge-to-be-32bit (a32bit i a8bit j)
  "merge 4 number in a 8bit array to 1 number in a 32bit array"
  (let ((result (gensym)))
    `(let ((,result 0))
       (setf (ldb (byte 8 24) ,result) (aref ,a8bit ,j)
             (ldb (byte 8 16) ,result) (aref ,a8bit (+ ,j 1))
             (ldb (byte 8 8) ,result) (aref ,a8bit (+ ,j 2))
             (ldb (byte 8 0) ,result) (aref ,a8bit (+ ,j 3))
             (aref ,a32bit ,i) ,result))))


(defmacro merge-to-be-64bit (a64bit i a8bit j)
  "merge 4 number in a 8bit array to 1 number in a 64bit array"
  (let ((result (gensym)))
    `(let ((,result 0))
       ,@(loop for i from 0 below 8
            collect `(setf (ldb (byte 8 ,(* 8 (- 7 i))) ,result) (aref ,a8bit (+ ,j ,i))))
       (setf (aref ,a64bit ,i) ,result))))


(defmacro expand-64bit-to-le-vector (size)
  "expand a 64bit number to a 8bit array"
  (let ((result (gensym)))
    `(let ((,result (* ,size 8)))
       (vector ,@(loop for i from 0 below 8
                    collect `(ldb (byte 8 ,(* i 8)) ,result))))))


(defmacro expand-128bit-to-le-vector (size)
  "expand a 128bit number to a 8bit array"
  (let ((result (gensym)))
    `(let ((,result (* ,size 8)))
       (vector ,@(loop for i from 0 below 16
                    collect `(ldb (byte 8 ,(* i 8)) ,result))))))


(defmacro expand-64bit-to-be-vector (size)
  "expand a 64bit number to a 8bit array"
  (let ((result (gensym)))
    `(let ((,result (* ,size 8)))
       (vector ,@(loop for i from 0 below 8
                    collect `(ldb (byte 8 ,(- 56 (* i 8))) ,result))))))


(defmacro expand-128bit-to-be-vector (size)
  "expand a 128bit number to a 8bit array"
  (let ((result (gensym)))
    `(let ((,result (* ,size 8)))
       (vector ,@(loop for i from 0 below 16
                    collect `(ldb (byte 8 ,(- 120 (* i 8))) ,result))))))


(declaim (inline convert-to-32bit-le-array))
(defun convert-to-32bit-le-array (a32bit a8bit &optional (len (* 64 *block*)) (size nil))
  "convert the origin 8bit array to 32bit array, and fill the extra 8bit special"
  (let ((j 0))
    (if size (setf a8bit (concatenate 'vector (pad (subseq a8bit 0 len) (calc-padding-64 len)) (expand-64bit-to-le-vector size))))
    (dotimes (i (/ (length a8bit) 4))
      (setf j (* i 4))
      (merge-to-le-32bit a32bit i a8bit j))))


(declaim (inline convert-to-64bit-le-array))
(defun convert-to-64bit-le-array (a64bit a8bit &optional (len (* 64 *block*)) (size nil))
  "convert the origin 8bit array to 64bit array, and fill the extra 8bit special"
  (let ((j 0))
    (if size (setf a8bit (concatenate 'vector (pad (subseq a8bit 0 len) (calc-padding-128 len)) (expand-128bit-to-le-vector size))))
    (dotimes (i (/ (length a8bit) 8))
      (setf j (* i 8))
      (merge-to-le-64bit a64bit i a8bit j))))


(declaim (inline convert-to-32bit-be-array))
(defun convert-to-32bit-be-array (a32bit a8bit &optional (len (* 64 *block*)) (size nil))
  "convert the origin 8bit array to 32bit array, and fill the extra 8bit special"
  (let ((j 0))
    (if size (setf a8bit (concatenate 'vector (pad (subseq a8bit 0 len) (calc-padding-64 len)) (expand-64bit-to-be-vector size))))
    (dotimes (i (/ (length a8bit) 4))
      (setf j (* i 4))
      (merge-to-be-32bit a32bit i a8bit j))))


(declaim (inline convert-to-64bit-be-array))
(defun convert-to-64bit-be-array (a64bit a8bit &optional (len (* 64 *block*)) (size nil))
  "convert the origin 8bit array to 64bit array, and fill the extra 8bit special"
  (let ((j 0))
    (if size (setf a8bit (concatenate 'vector (pad (subseq a8bit 0 len) (calc-padding-128 len)) (expand-128bit-to-be-vector size))))
    (dotimes (i (/ (length a8bit) 8))
      (setf j (* i 8))
      (merge-to-be-64bit a64bit i a8bit j))))


(defmacro convert-string-to-byte (str &key (encoding :utf8))
  "convert string to a 8-bit array"
  `(let ((result (make-array 64 :fill-pointer 0 :adjustable t :element-type '(unsigned-byte 8))))
     (loop for i across ,str
        for v = ([8]split ,(case encoding
                             (:ascii `(char-code i))
                             (otherwise `(clo-coding.utf8::encode i))))
        do (loop for j in v do (vector-push-extend j result)))
     result))
