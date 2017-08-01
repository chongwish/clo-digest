# NAME

clo-digest - A digest library for common lisp

# SYNOPSIS

    clo => Common Lisp Only
    digest => The algorithm of digest include md5/sha1/sha2 family/blake2 b&s

# Usage

    # load to system
    # link to the asd or ql path
    $> ln -s {clo-operator-path} {asd/ql-path}
    # or copy
    $> copy {clo-operator-path} {asd/ql-path}

    CL-User> (clo-digest.md5:text "你好")
    "7ECA689F0D3389D9DEA66AE112E5CFD7"
    CL-User> (clo-digest.sha2.512:file "~/Videos/animation/demo/demo.mp4")
    "0BAC51A398F1F67A9F0E5551522602611D40169B27CBF3F50F88E1E3E764B6BCAEB4BE88F57EC57E56E2AC398CBC93CFFAE38D5521604354D831E77666C6A4E3"

# Performance

    $> ls -lh ~/Videos/animation/demo
    -rw-r--r-- 1 chongwish chongwish 144M Sep  5  2014 demo.wmv
    $> screenfetch
    chongwish@gentoo src % screenfetch 
             -/oyddmdhs+:.                chongwish@gentoo.local
         -odNMMMMMMMMNNmhy+-`             OS: Gentoo 
       -yNMMMMMMMMMMMNNNmmdhy+-           Kernel: x86_64 Linux 4.9.34-gentoo
     `omMMMMMMMMMMMMNmdmmmmddhhy/`        Uptime: 9d 18h 12m
     omMMMMMMMMMMMNhhyyyohmdddhhhdo`      Packages: 1060
    .ydMMMMMMMMMMdhs++so/smdddhhhhdm+`    Shell: zsh 5.2
     oyhdmNMMMMMMMNdyooydmddddhhhhyhNd.   Resolution: 1920x1080
      :oyhhdNNMMMMMMMNNNmmdddhhhhhyymMh   DE: KDE5
        .:+sydNMMMMMNNNmmmdddhhhhhhmMmy   WM: KWin
           /mMMMMMMNNNmmmdddhhhhhmMNhs:   GTK Theme: Adwaita [GTK2/3]
        `oNMMMMMMMNNNmmmddddhhdmMNhs+`    Icon Theme: oxygen
      `sNMMMMMMMMNNNmmmdddddmNMmhs/.      Font: monofur Regular
     /NMMMMMMMMNNNNmmmdddmNMNdso:`        CPU: Intel Core i5-4200U CPU @ 1.6GHz
    +MMMMMMMNNNNNmmmmdmNMNdso/-           RAM: 2067MiB / 11699MiB
    MNNNNNNNmmmmmNNMmhs+/-`              
    /hMMNNNNNNNNMNdhs++/-`               
    `/ohdmmddhys+++/:.`                  
      `-//////:--.                       
    CL-User> (time (clo-digest.sha2.512:file "~/Videos/animation/demo/demo.wmv"))
    3.732 seconds of real time
    3.053000 seconds of total run time (2.975000 user, 0.078000 system)
    [ Run times consist of 0.101 seconds GC time, and 2.952 seconds non-GC time. ]
    81.81% CPU
    8,563,731,543 processor cycles
    750,139,664 bytes consed
    "C891330BBF9DBA9A5D0C745FED32F29B14248C78520DBBA6A3768AB86F09C078CACD154882E2845B074908436AFBF27AE393CBE1B8EDD8386D799846D8E55733"
    $> time sha512sum ~/Videos/animation/demo/demo.wmv
    sha512sum ~/Videos/animation/demo/demo.wmv  0.82s user 0.02s system 99% cpu 0.838 total
    c891330bbf9dba9a5d0c745fed32f29b14248c78520dbba6a3768ab86f09c078cacd154882e2845b074908436afbf27ae393cbe1b8edd8386d799846d8e55733
