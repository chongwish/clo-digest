(defpackage clo-digest-asd
  (:use :cl
        :asdf))

(in-package clo-digest-asd)

(defsystem clo-digest
  :version "0.1"
  :author "chongwish"
  :licence "BSD"
  :description "A Digest Library for Common Lisp"
  :components ((:file "main"
                :pathname "src/main"
                :depends-on ("lib"))
               (:module "lib"
                :pathname "src"
                :components ((:file "base")
                             (:file "md5")
                             (:file "sha1")
                             (:module "sha2"
                              :pathname "sha2"
                              :components ((:file "32bit")
                                           (:file "224")
                                           (:file "256")
                                           (:file "64bit")
                                           (:file "384")
                                           (:file "512")))
                             (:file "blake2s")
                             (:file "blake2b"))))
  :depends-on ("clo-operator" "clo-coding"))

