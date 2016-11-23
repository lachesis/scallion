Scallion
========
Scallion lets you create .onion addresses for [Tor's](https://www.torproject.org/) [hidden services](https://www.torproject.org/docs/hidden-services) using OpenCL. It is based in part on [shallot](https://github.com/katmagic/Shallot) and inspired by [vanitygen](https://github.com/samr7/vanitygen). The OpenCL SHA-1 implementation was adapted from [NearSHA](http://cr.yp.to/nearsha.html).

Scallion runs on Mono (tested in Arch Linux) and .NET 3.5 (tested on Windows 7 and Server 2008). It includes components from [OpenTK](http://www.opentk.com/) and [OpenSSL-net](http://openssl-net.sourceforge.net/).

Scallion is currently in beta stage and under active development. Nevertheless, we feel that it is ready for use. Improvements are expected primarily in performance, user interface, and ease of installation, not in the overall algorithm used to generate keys.

Scallion is available under the MIT licence. If you use code from this project in your own projects, we'd appreciate hearing about it at scallion@aftbit.com. If you have any issues, please open a ticket here. You might also try the #scallion channel on freenode.

**Note**: I am now generating addresses using the [secure remote generation](#SRKG) feature for a [small fee](saas.md).

Please send any donations to 1onion1PNeM2x9LhdqWn6uVFyU2iSpy7M.

FAQ
---
Here are some frequently asked (or anticipated :) questions and their answers:

- What are valid characters?

    Tor .onion addresses use [Base32](http://www.ietf.org/rfc/rfc4648.txt), consisting of all letters and the digits 2 through 7, inclusive. They are case-insensitive.

- Can you use Bitcoin ASICs (e.g. Jalapeno, KnC) to accelerate this process?

    Sadly, no. While the process Scallion uses is conceptually similar (increment a nonce and check the hash), the details are different (SHA-1 vs double SHA-256 for Bitcoin). Furthermore, Bitcoin ASICs are as fast as they are because they are extremely taylored to Bitcoin mining applications. For example, here's the [datasheet](https://bitmine.ch/wp-content/uploads/2013/11/CoinCraft-A1.pdf) for the CoinCraft A-1, an ASIC that never came out, but is probably indicitive of the general approach. The microcontroller sends work in the form of the final 128-bits of a Bitcoin block, the hash midstate of the previous bits, a target difficulty, and the maximum nonce to try. The ASIC chooses the location to insert the nonce, and it chooses what blocks meet the hash. Scallion has to insert the nonce in a different location, and it checks for a pattern match rather than just "lower than XXXX".

- How can you use multiple devices?

    Run multiple Scallion instances. :) Scallion searches are probabilistic, so you won't be repeating work with the second device. True multi-device support wouldn't be too difficult, but it also wouldn't add much. I've run several scallion instances in [tmux](http://tmux.sourceforge.net/) or [screen](https://www.gnu.org/software/screen/) with great success. You'll just need to manually abort all the jobs when one finds a pattern (or write a shell script to monitor the output file and kill them all when it sees results).

Dependancies
------------
- OpenCL and relevant drivers installed and configured. Refer to your distribution's documentation.
- OpenSSL. For Windows, the prebuilt x86 DLLs are included

Binary Download
---------------
Just want the latest binary version? Grab it [here](https://github.com/lachesis/scallion/blob/binaries/scallion-v1.2.zip?raw=true).

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

<a name="SRKG"></a> Secure Remote Key Generation
------------------------------------------------
Many people have asked about the ability to perform [split-key generation](https://en.bitcoin.it/wiki/Split-key_vanity_address) like VanityGen supports. Unfortunately, as far as I understand it, RSA does not lend itself to split-key generation. However, I have implemented secure remote key generation. As it so happens, Scallion mines for onion addresses by changing the public key exponent on the fly. With the current configuration, a single public key is good for around 1 GH worth of work. So I've added the ability for Scallion to export a list of public key moduli. This list may then be sent to an untrusted 3rd party, who can use it to mine for onion addresses. They will then return a work file to you which contains the modulus and exponent that generates a matching onion address. You can then plug this into scallion and have it look up and output the private key for you.

### Usage Example

- Generate the public and private keys. The prefix doesn't matter, it is just used to guess how many keys to generate. My machine can generate ~50 keys per second. This is purely done on the CPU, no GPU required.
        
        [homebox]$ mono scallion.exe -m prefixab.work -s prefixab
        
        Generating that pattern will require approximately 549.756 gigahashes.
        That will require on average 516 public keys.
        Generating 2580 keys (for safety's sake).
        Generating key 0 of 2580...
        Generating key 100 of 2580...
        Generating key 200 of 2580...
        Generating key 300 of 2580...
        Generating key 400 of 2580...
        Generating key 500 of 2580...
        Generating key 600 of 2580...
        Generating key 700 of 2580...
        Generating key 800 of 2580...
        Generating key 900 of 2580...
        Generating key 1000 of 2580...
        Generating key 1100 of 2580...
        Generating key 1200 of 2580...
        Generating key 1300 of 2580...
        Generating key 1400 of 2580...
        Generating key 1500 of 2580...
        Generating key 1600 of 2580...
        Generating key 1700 of 2580...
        Generating key 1800 of 2580...
        Generating key 1900 of 2580...
        Generating key 2000 of 2580...
        Generating key 2100 of 2580...
        Generating key 2200 of 2580...
        Generating key 2300 of 2580...
        Generating key 2400 of 2580...
        Generating key 2500 of 2580...

- Send the "prefixab.work" file to to the 3rd party. Hold on to "prefixab.work.priv" as it contains the corresponding private keys.

- [3rdParty] Run the scallion search. The pattern here is the one that will actually be searched for. All normal scallion features can be used (multipattern, etc). This should support continuation (i.e. if the search crashes or you abort it, it should skip keys that have already been fully processed).

        [3rdParty]$ mono scallion.exe -m prefixab.work -o prefixab.out prefixab

- [3rdParty] Eventually you'll see results

        Cooking up some delicions scallions...
        Putting 1 patterns into 1 buckets.
        Using kernel optimized from file kernel.cl (Optimized4_9)
        Using work group size 64
        Compiling kernel... done.
        LoopIteration:81  HashCount:1358.95MH  Speed:510.5MH/s  Runtime:00:00:02  Predicted:00:00:01  CPU checking hash: prefixtqxqxyaxkk

        Ding!! Delicious scallions for you!!

        Public Modulus:  104034656471910639183441462048234882216377353714800760947183976268798558118989688383108389030276771390272538636166196053337028631327657483245868475254132027413294093926375303575995242086859106541594991222193169950069190845465874647730359497522886565212806839757713851504194745050022468490282136394605183653131
        Public Exponent: 1379077237
        Address/Hash: prefixabxqxyaxkk.onion

        init: 526ms / 1 (526ms, 1.9/s)
        cpu precompute: 22ms / 7 (3.14ms, 318.18/s)
        generate key: 0ms / 427 (0ms, 0/s)
        total without init: 2688ms / 1 (2688ms, 0.37/s)
        set buffers: 0ms / 81 (0ms, 0/s)
        write buffers: 2ms / 81 (0.02ms, 40500/s)
        read results: 2613ms / 81 (32.26ms, 31/s)
        check results: 26ms / 81 (0.32ms, 3115.38/s)

        505.56 million hashes per second

- [3rdParty] Now send the results file (prefixab.out above) to the original user

- Finally, you need to use scallion to look up the private key, update the exponent, and dump the final private key and onion hash.
        
        [homebox]$ mono scallion.exe -m prefixab.work -r prefixab.out -o prefixab.final 

        Ding!! Delicious scallions for you!!

        Public Modulus:  104034656471910639183441462048234882216377353714800760947183976268798558118989688383108389030276771390272538636166196053337028631327657483245868475254132027413294093926375303575995242086859106541594991222193169950069190845465874647730359497522886565212806839757713851504194745050022468490282136394605183653131
        Public Exponent: 1379077237
        Address/Hash: prefixabxqxyaxkk.onion

        -----BEGIN RSA PRIVATE KEY-----
        MIICXgIBAAKBgQCxz2AU5LV7tF9MAsc3FzrEiOuOUKwR4YSJ33MfwFiG5ASI+zxB
        uUekT4w6fiJ5o4ZRT1mr6ThqVJnbMOcMYbqDCbfGdDXgcr5BCAZzI7tZK5GDDZea
        aZGcOLubPQzddZaCoHhwpP6n2EhebvKPEDvXYc/WBArz6aJYidTh1KWSQQIETtNh
        BQKBgC2pREX4wvbgLfYocDUFmodhcPaE4cfEJD7ki8Fg0Nom3DYVtueQW2ks1EU5
        ufUoccHKDIw6DDJp9+Anwv7JkENi28G+ekUU0bez5rqPdxL0WSh3wlwEmfGxpMqA
        4UqVrt0XblGePPUvlnY4+ZT2h4Z6HpxaJG4BQW9e9Nb6w02hAkEA4nZ3OMwflru2
        hdpVoNgVoW6mx26eVtY0MY2P+cNKeogoEEfurM8ZaAfAfI3JVceNR4/ak3d4gRua
        sqCxcbHK3wJBAMkAaIj558mqjlK7/b4bcg782xWacDSncDwhqLzAd+UgCl5oXOLr
        0LhpS2ZXZ6usbLKM0UFN6WD4g70WXOsvZt8CQQCwN5CLunrzQH34mXMkpZoEiHqO
        QOfXCzkdOoN09MPF0d5oQKqtIxao8LAMvaYX61yqI6b0cvWYFIIV4tZM33xrAkAw
        vKb9wEDZbBYyCfwmVrFxbQurTx3QOIEVdA5Yquf71OrGOMBfUn7FLSTsIhelRR+h
        SXE8m99Bhfr+S8V1shR/AkEAzHIwul//eymSpRO3/uVFd4qeLl55dgUfE9OZi3JE
        85up4Awqikj+QF2S840dqnDYiTDfpkj01lb7t8x+O8A9jQ==
        -----END RSA PRIVATE KEY-----

### Performance

My ivybridge i7 can generate 51 keys per second using a single core. I'm not sure if the OpenSSL lib is thread-safe, but this could probably be improved if needed.

Each (1024-bit) key is output as a decimal encoded modulus (should have used hex, but too late now), taking 310 bytes per key. The private key is also output with the modulus, taking 1215 bytes per key.

Each key can provide 1 gigahash worth of exponents to mine. This could be improved by roughly a factor of two at the expense of code complexity and/or a large drop in mining hashrate. However, Scallion generates 5x as many keys as are needed in the average case to help ensure that the remote host won't run out of work. Remember, this is a probabilistic process.

In order to mine for an 8 character prefix, you'd need around 2580 keys, which would take around 1 minute to generate on a relatively modern CPU, and which would produce a public key file about 1 MB. The private key file would be about 3 MB. Finally, on a 520MH/s GPU (like my 5770) this prefix would take _on average_ around 17 minutes to mine.

In order to mine for a 9 character prefix, you'd need around 82565 keys, which would take around 30 minutes to generate on a relatively modern CPU, and which would produce a public key file about 24 MB. The private key file would be about 95 MB. Finally, on a 520 MH/s GPU (like my 5770) this prefix would take _on average_ around 10 hours to mine.

In order to mine for a 10 character prefix, you'd need around 2642160 keys, which would take around 15 hours to generate on a relatively modern CPU, and which would produce a public key file about 781 MB. The private key file would be about 3 GB. Finally, on a 520 MH/s GPU (like my 5770) this prefix would take _on average_ around 12 days and 12 hours to mine.

In order to mine for an 11 character prefix, you'd need around 84549200 keys, which would take around 19 days to generate on a relatively modern CPU, and which would produce a public key file about 24 GB. The private key file would be about 96 GB. Finally, on a 520 MH/s GPU (like my 5770) this prefix would take _on average_ around 400 days to mine.

There are some major potential space savings in the size of these files (e.g. using hex or a binary encoding for the keys).

The 3rd party mode mining performance is very similar to the normal mode. The keys are read in at startup and the full list is kept in RAM, and there is a small (< 5 MH/s for me) drop in hashrate because of the need to save used keys to the continuation file, but beyond that, it's identical.

### Service

Contact me at ```scallion@aftbit.com``` if you're interested in having me generate a key for you using this feature. I've drawn up a pricing table and some performance specifications at [saas.md](saas.md).

Speed
-----
On my nVidia Quadro K2000M, I see around 90 MH/s. With those speeds, I can generate a six character prefix in about six seconds on average. An eight character prefix would take about 1h 45m. To calculate the number of seconds required for a given prefix (on average), use this formula:

    seconds = 2^(5*length-1) / hashspeed 

My AMD Radeon HD5770 gets 520 MH/s.

My friend's AMD Radeon HD6850 gets 600 MH/s. That's a 300x speedup over shallot. With that speed, he can find an eight character prefix in just 15 minutes on average.

On a NVIDIA GTS 250, I get about 126-129 MH/s with a single-pattern match and about 101-119 MH/s with multi-pattern match.  With shallot I got about 500kH/s.

kH/s = thousand hashes per second.

MH/s = million hashes per second.

A quick way to check your average speed is to use a google search structured like this:

    (2^(5*8-1) / 97.3 million) seconds in hours
          |          |
          |          |
       lenght    speed as stated by scallion, in this case 97,3MH/s

Click here to [try the above formula on Wolfram Alpha]](http://www.wolframalpha.com/input/?i=%282%5E%285*8-1%29+%2F+97.3+million%29+seconds+in+hours)

Workgroups
--------
This will use your devices reported preferred work group size by default.  This is the most compatiable way for it to run, but you should experiment with the numbers to try to get the highest as possible for increased performance.


Security
--------
The keys generated by Scallion are quite similar to those generated by shallot. They have unusually large public exponents, but they are put through the full set of sanity checks recommended by PKCS #1 v2.1 via openssl's RSA_check_key function. In general, however, tor's (and Scallion's) default 1024-bit key is starting to [look a little small](https://lists.torproject.org/pipermail/tor-dev/2011-November/003033.html). Scallion supports several RSA key sizes, with optimized kernels for 1024b, 2048b, and 4096b. Other key sizes may work, but have not been tested.

Donations
---------
Feel free to direct donations to the Bitcoin address: `1FxQcu6vhpwsqcTjPsjK43CZ9vjnuk4Hmo`

