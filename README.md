Scallion
========
Scallion lets you create .onion addresses for [Tor's](https://www.torproject.org/) [hidden services](https://www.torproject.org/docs/hidden-services) using OpenCL. It is based in part on [shallot](https://github.com/katmagic/Shallot) and inspired by [vanitygen](https://github.com/samr7/vanitygen). The OpenCL SHA-1 implementation was adapted from [NearSHA](http://cr.yp.to/nearsha.html).

Scallion runs on Mono (tested in Arch Linux) and .NET 3.5 (tested on Windows 7 and Server 2008). It includes components from [OpenTK](http://www.opentk.com/) and [OpenSSL-net](http://openssl-net.sourceforge.net/).

Scallion is currently in beta stage and under active development. Nevertheless, we feel that it is ready for use. Improvements are expected primarily in performance, user interface, and ease of installation, not in the overall algorithm used to generate keys.

Scallion is available under the MIT licence. If you use code from this project in your own projects, we'd appreciate hearing about it at scallion@aftbit.com.

Dependancies
------------
- OpenCL and relevant drivers installed and configured. Refer to your distribution's documentation.
- OpenSSL. For Windows, the prebuilt x86 DLLs are included

Build Linux
-----------
    xbuild scallion.sln

Build Windows
-------------
1. Open 'scallion.sln' in VS Express for Desktop 2012
2. Build the solution, I did everything in debug mode.

Usage
-----
List devices

    $ mono scallion/bin/Debug/scallion.exe -l

Generate a hash

    $ mono scallion/bin/Debug/scallion.exe -d 0 prefix
    Cooking up some delicions scallions...
    LoopIteration:15  HashCount:251.66MH  Speed:89.2MH/s  Runtime:00:00:02  Predicted:00:00:12
    Ding!! Delicions scallions for you!!

    Exponent: 37074435
    Address/Hash: prefix2bp7lfuuvp

    -----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQDVNxlMDVXQ6EjRLubgMUkhVeVYigEPZ4BLUhzNRp4MEMgVQHLP
    GRlMc2yK29Q8fuvC1o2zJS8IF6RbXyB9Sdyuzh43st2CZeTMEWbkz6NNAJz+8UHh
    1I35CWx5p4wlsw2eZx+wM7s6Ll4762pV21qolxqHoIefOsIso0AHixYPrQIEAjW2
    AwKBgAEqghqEMZ2cedXc+AIKmZebbzJyWvfp9W9HRHXn6c7U0mYFNHXnAjR8KR6r
    2w2IGS4LxKi360XRr70gIUw9mr9tiOlMjppkqwu7HSB0ldzCitNkVLRiV+TZQFXc
    g6xxZZxX2giZoBThCq8g85/V+AyLRZK9ZdC+GkBP0YPgy8/rAkEA/j8vGpo/OkZq
    3ucytAZYb+1HomUiSbh+oxMwxT84xQeSqIg/BsvWixPhuOY+7HNzdZVN458H8UXC
    zSWNmmmnYQJBANave5NDwnw5w/dARWMJsAYRc7GA/wx86o/+qmw/8Q6GBkFdUqcM
    2Vw0HzDIq7q1UwYBznlRCI1Wgyd5+OwDZ80CQQDaewQ811o3/8StlKLvpify+fkQ
    81j0GdoUJgYCz3nDEp6sCPvg3aSI7b195odY4L3d0pQ4SnPj0zGJMFdqcwFLAkBj
    A/NC23ZfVx8u1JzRojkwuE4ZAWmALIubP+iwS6I5Yj4/wz2R1veYBQX1TKNT8sOy
    XA8cQ53ybVp+z39eWCPHAkAz1Sv1IOuGWS/KrC0BUQ7vtwf3z5yMUX3kMS1JF9Bf
    TbEyV92GNkwxcVzMRCSeaqZXQVUIaWdbPnjYq4T6Heal
    -----END RSA PRIVATE KEY-----


    init: 423ms / 1 (423ms, 2.36/s)
    generate key: 840ms / 45 (18.67ms, 53.57/s)
    cpu precompute: 9ms / 45 (0.2ms, 5000/s)
    total without init: 2828ms / 1 (2828ms, 0.35/s)
    set buffers: 0ms / 15 (0ms, 0/s)
    write buffers: 2ms / 15 (0.13ms, 7500/s)
    run kernel: 0ms / 15 (0ms, 0/s)
    read results: 2812ms / 15 (187.47ms, 5.33/s)
    check results: 5ms / 15 (0.33ms, 3000/s)

    88.99 million hashes per second

Multipattern Hashing
--------------------
Scallion supports finding one or more of multiple patterns through a primitive regex syntax. Only character classes (ex. [abcd]) are supported. The "." character represents any character. Onion addresses are always 16 characters long, so a suffix can be found by prepending the correct number of dots.  You can also find a suffix by putting a $ at the end of the match. Finally, the pipe syntax (ex. "prefix|pattern") can be used. Adding more patterns (within reason) will NOT produce a significant decrease in speed because the internal implementation has a constant time lookup. Using multiple patterns may produce an ~8% decline in total hash speed, but many regexps will produce a single pattern on the GPU.
 
Some use cases with examples:
- Generate a prefix followed by a number for better readability:
   
    mono scallion.exe prefix[234567]

- Search for several patterns at once (n.b. -c causes scallion to continue generating even once it gets a hit)
    
    mono scallion.exe -c prefix scallion hashes

- Search for a suffix
   
   mono scallion.exe ..........suffix
   
   mono scallion.exe suffix$
   
   mono scallion.exe "suffixa$|suffixb$|prefixa|prefixb|a.suffix$|a.test.$"


Speed
-----
On my nVidia Quadro K2000M, I see around 90 MH/s. With those speeds, I can generate a six character prefix in about six seconds on average. An eight character prefix would take about 1h 45m. To calculate the number of seconds required for a given prefix (on average), use this formula:

    seconds = 2^(5*length-1) / hashspeed 
 
My friend's AMD Radeon HD6850 gets 600 MH/s. That's a 300x speedup over shallot. With that speed, he can find an eight character prefix in just 15 minutes on average.

On a NVIDIA GTS 250, I get about 126-129 MH/s with a single-pattern match and about 101-119 MH/s with multi-pattern match.  With shallot I got about 500kH/s.

kH/s = thousand hashes per second.

MH/s = million hashes per second.


Workgroups
--------
This will use your devices reported preferred work group size by default.  This is the most compatiable way for it to run, but you should experiment with the numbers to try to get the highest as possible for increased performance.


Security
--------
The keys generated by Scallion are quite similar to those generated by shallot. They have unusually large public exponents, but they are put through the full set of sanity checks recommended by PKCS #1 v2.1 via openssl's RSA_check_key function. In general, however, tor's (and Scallion's) default 1024-bit key is starting to [look a little small](https://lists.torproject.org/pipermail/tor-dev/2011-November/003033.html). Scallion supports several RSA key sizes, with optimized kernels for 1024b, 2048b, and 4096b. Other key sizes may work, but have not been tested.

Donations
---------
Feel free to direct donations to the Bitcoin address: 1E82DM9mxvvfMfVAwpDANbkwXc2uWvQD1

