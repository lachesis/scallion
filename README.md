2020 Project Update
===================
Scallion was a hobby project to learn OpenCL and RSA. **We are not currently maintaining scallion**. It has bitrotted in two important ways:

1. Tor has moved on to [v3 Onion addresses](https://github.com/torproject/torspec/blob/master/rend-spec-v3.txt), which scallion does not support. Old v2 addresses will stop working in [October of 2021](https://thehiddenwiki.com/new-long-v3-onion-services-version-3-hidden-service-links-on-the-hidden-wiki/). The new spec uses different cryptographic primitives and is overall more complicated. The trick we use to generate batches of RSA keys on the GPU does not work in the same way for the new ECDSA keys required. It _is_ possible to generate similar (but not compatible) ECDSA keys on the GPU, for Bitcoin address generation. See [vanitygen-plus](https://github.com/exploitagency/vanitygen-plus) or the older oclvanitygen. For a list of (CPU-based) vanity gen tools for that work for Tor v3 hidden services, see [this blog post](https://www.jamieweb.net/blog/onionv3-vanity-address/).
2. The version of OpenSSL we rely on has been deprecated and is unavailable in most modern OSes. It isn't straightforward to upgrade, as we use some low-level math functions in OpenSSL that are not available in the C# bindings for the newer versions. I personally run Scallion using the nvidia dockerfile, which is based on Ubuntu 16.04 Xenial, which still ships the outdated OpenSSL. This is only an option for Nvidia GPU users, however. You could also try building the outdated OpenSSL library and linking against it directly, or running an older version of your OS from a live USB or VM (with PCI-e passthrough).

With enough attention and effort, it would be possible to overcome both of the challenges given above. We could implement support for the GPU ECDSA key generation algorithm to gain Tor v3 support. We could update OpenSSL and replace the math functions with a different library, or make our own managed code wrapper for the OpenSSL library. However, it would likely be better to add support for v3 onion addresses to a maintained project like [vanitygen-plus](https://github.com/exploitagency/vanitygen-plus).

Scallion
========
Scallion lets you create vanity GPG keys and .onion addresses (for [Tor's](https://www.torproject.org/) [hidden services](https://www.torproject.org/docs/hidden-services)) using OpenCL.

Scallion runs on Mono (tested in Arch Linux) and .NET 3.5+ (tested on Windows 7 and Server 2008).

Scallion is currently in beta stage and under active development. Nevertheless, we feel that it is ready for use. Improvements are expected primarily in performance, user interface, and ease of installation, not in the overall algorithm used to generate keys.

Scallion is available under the MIT license. If you use code from this project in your own projects, we'd appreciate hearing about it at scallion@aftbit.com.

FAQ
---
Here are some frequently asked questions and their answers:

- Why generate GPG keys?

   Scallion was used to find collisions for every 32bit key id in the Web of Trust's strong set demonstrating how insecure 32bit key ids are. There was/is [a talk at DEFCON](https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Klafter) ([video](https://www.youtube.com/watch?v=Ow-YcP_KsIw)) and additional info can be found at [https://evil32.com/](https://evil32.com/).

- What are valid characters?

    Tor .onion addresses use [Base32](http://www.ietf.org/rfc/rfc4648.txt), consisting of all letters and the digits 2 through 7, inclusive. They are case-insensitive.

    GPG fingerprints use [hexadecimal](http://en.wikipedia.org/wiki/Hexadecimal), consisting of the digits 0-9 and the letters A-F.

- Can you use Bitcoin ASICs (e.g. Jalapeno, KnC) to accelerate this process?

    Sadly, no. While the process Scallion uses is conceptually similar (increment a nonce and check the hash), the details are different (SHA-1 vs double SHA-256 for Bitcoin). Furthermore, Bitcoin ASICs are as fast as they are because they are extremely tailored to Bitcoin mining applications. For example, here's the [datasheet](https://bitmine.ch/wp-content/uploads/2013/11/CoinCraft-A1.pdf) for the CoinCraft A-1, an ASIC that never came out, but is probably indicitive of the general approach. The microcontroller sends work in the form of the final 128-bits of a Bitcoin block, the hash midstate of the previous bits, a target difficulty, and the maximum nonce to try. The ASIC chooses the location to insert the nonce, and it chooses what blocks meet the hash. Scallion has to insert the nonce in a different location, and it checks for a pattern match rather than just "lower than XXXX".

- How can you use multiple devices?

    Run multiple Scallion instances. :smile: Scallion searches are probabilistic, so you won't be repeating work with the second device. True multi-device support wouldn't be too difficult, but it also wouldn't add much. I've run several scallion instances in [tmux](http://tmux.sourceforge.net/) or [screen](https://www.gnu.org/software/screen/) with great success. You'll just need to manually abort all the jobs when one finds a pattern (or write a shell script to monitor the output file and kill them all when it sees results).

Dependencies
------------
- OpenCL and relevant drivers installed and configured. Refer to your distribution's documentation.
- OpenSSL. For Windows, the prebuilt x86 DLLs are included
- On windows only, [VC++ Redistributable 2008](https://www.microsoft.com/en-us/download/details.aspx?id=5582)

Binary Download
---------------
Just want the latest binary version? Grab it [here](https://github.com/lachesis/scallion/raw/binaries/scallion-v2.0.zip).

Build Linux
-----------
Prerequisites

- Get the latest mono for your linux distribution:

    http://www.mono-project.com/download/

- Install Common dependencies:

    ```
    sudo apt-get update
    sudo apt-get install libssl-dev mono-devel
    ```

- AMD/OpenSource build
    ```sudo apt-get install ocl-icd-opencl-dev```

- Nvidia build
    ```sudo apt-get install nvidia-opencl-dev nvidia-opencl-icd```

- Finally
    ```msbuild scallion.sln```


Docker Linux (nvidia GPUs only)
-----------

1. Have the [nvidia-docker container](https://github.com/NVIDIA/nvidia-docker) runtime

2. Build the container:
    ```
    docker build -t scallion -f Dockerfile.nvidia .
    ```
3. Run:
   ```
   docker run --runtime=nvidia -ti --rm scallion -l
   ```
   <a href="https://user-images.githubusercontent.com/9354925/53215957-37ed6100-3653-11e9-97d0-97a6c06eabe4.png" target="_blank">screenshot of expected output</a>

Build Windows
-------------
1. Open 'scallion.sln' in VS Express for Desktop 2012
2. Build the solution, I did everything in debug mode.

Usage
-----
__Restarting Scallion during a search will not lose "progress". It is a probabilistic search and Scallion does not make "progress"__

List devices

    $ mono scallion/bin/Debug/scallion.exe -l

Generate a hash

    $ mono scallion/bin/Debug/scallion.exe -d 0 prefix
    Cooking up some delicious scallions...
    Using kernel optimized from file kernel.cl (Optimized4)
    Using work group size 128
    Compiling kernel... done.
    Testing SHA1 hash...
    CPU SHA-1: d3486ae9136e7856bc42212385ea797094475802
    GPU SHA-1: d3486ae9136e7856bc42212385ea797094475802
    Looks good!
    LoopIteration:40  HashCount:671.09MH  Speed:9.5MH/s  Runtime:00:01:10  Predicted:00:00:56  Found new key! Found 1 unique keys.
    <XmlMatchOutput>
      <GeneratedDate>2014-08-05T07:14:50.329955Z</GeneratedDate>
      <Hash>prefix64kxpwmzdz.onion</Hash>
      <PrivateKey>-----BEGIN RSA PRIVATE KEY-----
    MIICXAIBAAKBgQCmYmTnwGOCpsPOqvs5mZQbIM1TTqOHK1r6zGvpk61ZaT7z2BCE
    FPvdTdkZ4tQ3/95ufjhPx7EVDjeJ/JUbT0QAW/YflzUfFJuBli0J2eUJzhhiHpC/
    1d3rb6Uhnwvv3xSnfG8m7LeI/Ao3FLtyZFgGZPwsw3BZYyJn3sD1mJIJrQIEB/ZP
    ZwKBgCTUQTR4zcz65zSOfo95l3YetVhfmApYcQQd8HTxgTqEsjr00XzW799ioIWt
    vaKMCtJlkWLz4N1EqflOH3WnXsEkNA5AVFe1FTirijuaH7e46fuaPJWhaSq1qERT
    eQT1jY2jytnsJT0VR7e2F83FKINjLeccnkkiVknsjrOPrzkXAkEA0Ky+vQdEj64e
    iP4Rxc1NreB7oKor40+w7XSA0hyLA3JQjaHcseg/bqYxPZ5J4JkCNmjavGdM1v6E
    OsVVaMWQ7QJBAMweWSWtLp6rVOvTcjZg+l5+D2NH+KbhHbNLBcSDIvHNmD9RzGM1
    Xvt+rR0FA0wUDelcdJt0R29v2t19k2IBA8ECQFMDRoOQ+GBSoDUs7PUWdcXtM7Nt
    QW350QEJ1hBJkG2SqyNJuepH4PIktjfytgcwQi9w7iFafyxcAAEYgj4HZw8CQAUI
    3xXEA2yZf9/wYax6/Gm67cpKc3sgKVczFxsHhzEml6hi5u0FG7aNs7jQTRMW0aVF
    P8Ecx3l7iZ6TeakqGhcCQGdhCaEb7bybAmwQ520omqfHWSte2Wyh+sWZXNy49EBg
    d1mBig/w54sOBCUHjfkO9gyiANP/uBbR6k/bnmF4dMc=
    -----END RSA PRIVATE KEY-----
    </PrivateKey>
      <PublicModulusBytes>pmJk58BjgqbDzqr7OZmUGyDNU06jhyta+sxr6ZOtWWk+89gQhBT73U3ZGeLUN//ebn44T8exFQ43ifyVG09EAFv2H5c1HxSbgZYtCdnlCc4YYh6Qv9Xd62+lIZ8L798Up3xvJuy3iPwKNxS7cmRYBmT8LMNwWWMiZ97A9ZiSCa0=</PublicModulusBytes>
      <PublicExponentBytes>B/ZPZw==</PublicExponentBytes>
    </XmlMatchOutput>
    init: 491ms / 1 (491ms, 2.04/s)
    generate key: 1193ms / 6 (198.83ms, 5.03/s)
    cpu precompute: 10ms / 6 (1.67ms, 600/s)
    total without init: 70640ms / 1 (70640ms, 0.01/s)
    set buffers: 0ms / 40 (0ms, 0/s)
    write buffers: 3ms / 40 (0.08ms, 13333.33/s)
    read results: 67442ms / 40 (1686.05ms, 0.59/s)
    check results: 185ms / 40 (4.63ms, 216.22/s)

    9.50 million hashes per second

    Stopping the GPU and shutting down...

Multipattern Hashing
--------------------
Scallion supports finding one or more of multiple patterns through a primitive regex syntax. Only character classes (ex. `[abcd]`) are supported. The `.` character represents any character. Onion addresses are always 16 characters long and GPG fingerprints are always 40 characters. You can find a suffix by putting `$` at the end of the match (ex. `DEAD$`). Finally, the pipe syntax (ex. `pattern1|pattern2`) can be used to find multiple patterns. Searching for multible patterns (within reason) will NOT produce a significant decrease in speed. Many regexps will produce a single pattern on the GPU and result in no speed reduction.

Some use cases with examples:
- Generate a prefix followed by a number for better readability:

        mono scallion.exe prefix[234567]

- Search for several patterns at once (n.b. -c causes scallion to continue generating even once it gets a hit)

        mono scallion.exe -c prefix scallion hashes
        mono scallion.exe -c "prefix|scallion|hashes"

- Search for the suffix "badbeef"

        mono scallion.exe .........badbeef
        mono scallion.exe --gpg badbeef$ # Generate GPG key

- Complicated self explanatory example:

        mono scallion.exe "suffixa$|suffixb$|prefixa|prefixb|a.suffix$|a.test.$"

How does Scallion work?
--------------------
At a high level Scallion works as follows:

1. Generate RSA key using OpenSSL on the CPU
2. Send the key to the GPU
3. Increase the key's public exponent
4. Hash the key
5. If the hashed key is not a partial collision go to step 3
6. If the key does not pass the sanity checks recommended by PKCS #1 v2.1 (checked on the CPU) go to step 3
7. Brand new key with partial collision!

The basic algorithm is described above. Speed / performance is the result of massive parallelization, both
on the GPU and the CPU.

Speed / Performance
--------------------
__It is important to realize that Scallion preforms a probabilistic search. Actual times may very significantly from predicated__

The inital RSA key generation is done the CPU. An ivybridge i7 can generate 51 keys per second using a single core. Each key can provide 1 gigahash worth of exponents to mine and a decent CPU can keep up with several GPUs as it is currently implemented.

SHA1 hashing is done on the GPU. The hashrates for several GPUs we have tested are below (grouped by manufacturer and sorted by power):

GPU                           | Speed
----------------------------- | -------------
Intel i7-2620M                | 9.9 MH/s
Intel i5-5200U                | 118 MH/s
NVIDIA GT 520                 | 38.7 MH/s
NVIDIA Quadro K2000M          | 90 MH/s
NVIDIA GTS 250                | 128 MH/s
NVIDIA GTS 450                | 144 MH/s
NVIDIA GTX 670                | 480 MH/s
NVIDIA GTX 970                | 2350 MH/s
NVIDIA GTX 980                | 3260 MH/s
NVIDIA GTX 1050 (M)           | 1400 MH/s
NVIDIA GTX 1070               | 4140 MH/s
NVIDIA GTX 1070 TI            | 5100 MH/s
NVIDIA GTX TITAN X            | 4412 MH/s
NVIDIA GTX 1080               | 5760 MH/s
NVIDIA Tesla V100             | 11646 MH/s
AMD A8-7600 APU               | 120 MH/s
AMD Radeon HD5770             | 520 MH/s
AMD Radeon HD6850             | 600 MH/s
AMD Radeon RX 460             | 840 MH/s
AMD Radeon RX 470             | 957 MH/s
AMD Radeon R9 380X            | 2058 MH/s
AMD FirePro W9100             | 2566 MH/s
AMD Radeon RX 480             | 2700 MH/s
AMD Radeon RX 580             | 3180 MH/s
AMD Radeon R9 Nano            | 3325 MH/s
AMD Vega Frontier Edition     | 7119 MH/s

MH/s = million hashes per second

Its worth noting that Intel has released OpenCL drivers for its processors and short collisions can be found on the CPU.

To calculate the number of seconds required for a given partial collision (on average), use the formula:

Type             | Estimated time
-----------------| --------------
GPG Key          |  2^(4*length-1) / hashspeed
.onion Address   |  2^(5*length-1) / hashspeed

For example on my nVidia Quadro K2000M, I see around 90 MH/s. With those speed I can generate an eight character .onion prefix in about 1h 41m, `2^(5*8-1)/90 million = 101 minutes`.

Workgroup Size
--------
Scallion will use your devices reported preferred work group size by default. This is a reasonable default but experimenting with the workgroup may increase performance.

Security
--------
The keys generated by Scallion are quite similar to those generated by shallot. They have unusually large public exponents, but they are put through the full set of sanity checks recommended by PKCS #1 v2.1 via openssl's RSA_check_key function. Scallion supports several RSA key sizes, with optimized kernels for 1024b, 2048b, and 4096b. Other key sizes may work, but have not been tested.

Thanks / References
---------
* Scallion is based in part on [shallot](https://github.com/katmagic/Shallot) and inspired by [vanitygen](https://github.com/samr7/vanitygen)
* The OpenCL SHA-1 implementation was adapted from [NearSHA](http://cr.yp.to/nearsha.html)
* Includes components from [OpenTK](http://www.opentk.com/) and [OpenSSL-net](http://openssl-net.sourceforge.net/)

Donations
---------
Feel free to direct donations to the Bitcoin address: `1FxQcu6vhpwsqcTjPsjK43CZ9vjnuk4Hmo`

