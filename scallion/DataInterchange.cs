using System;
using System.Linq;
using System.Collections.Generic;
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.Xml.Serialization;

namespace scallion
{
	public class XmlPublicKey
	{
		public XmlPublicKey() { }
		public XmlPublicKey(BigNumber publicModulus)
		{
			PublicModulus = publicModulus;
		}

        [XmlIgnore]
		public BigNumber PublicModulus { get; set; }

        /// <summary>
        /// This is for serialization!
        /// </summary>
		public byte[] PublicModulusBytes
		{ 
			get {
				byte[] bytes = new byte[PublicModulus.Bytes];
				PublicModulus.ToBytes(bytes);
				return bytes;
			}

			set {
				PublicModulus = BigNumber.FromArray(value);
			}
		}
	}

	public class XmlKeyDictionary
	{
		public XmlKeyDictionary()
		{
			PublicModToPrivateKeyPEMMap = new List<KeyValuePair<byte[], string>>();
		}

		// Map the public modulus (as a byte array) to the private key (as a base64-encoded string)
		public List<KeyValuePair<byte[], string>> PublicModToPrivateKeyPEMMap { get; set; }

		public void AddKey(RSAWrapper rsa)
		{
			byte[] pubMod = new byte[rsa.Rsa.PublicModulus.Bytes];
			rsa.Rsa.PublicModulus.ToBytes(pubMod);

			string privKey = rsa.Rsa.PrivateKeyAsPEM;

			PublicModToPrivateKeyPEMMap.Add(new KeyValuePair<byte[], string>(pubMod, privKey));
		}

		public RSAWrapper FindKey(BigNumber publicModulus)
		{
			byte[] pubMod = new byte[publicModulus.Bytes];
			publicModulus.ToBytes(pubMod);

			foreach (var kvp in PublicModToPrivateKeyPEMMap) {
				if (Enumerable.SequenceEqual(kvp.Key, pubMod)) { // TODO: determine if this is too slow
					RSAWrapper rsa = new RSAWrapper();
					rsa.FromPrivateKeyPEM(kvp.Value);
					return rsa;
				}
			}

			return null; // it failed
		}
	}

	public class XmlMatchOutput
	{
		public XmlMatchOutput() { }

		public DateTime GeneratedDate { get; set; }
        [XmlIgnore]
		public BigNumber PublicModulus { get; set; }
        [XmlIgnore]
		public BigNumber PublicExponent { get; set; }
		public string Hash { get; set; }
		public string PrivateKey { get; set; }
        
        /// <summary>
        /// This is for serialization!
        /// </summary>
		public byte[] PublicModulusBytes {
			get {
				byte[] bytes = new byte[PublicModulus.Bytes];
				PublicModulus.ToBytes(bytes);
				return bytes;
			}

			set {
				PublicModulus = BigNumber.FromArray(value);
			}
		}

        /// <summary>
        /// This is for serialization!
        /// </summary>
		public byte[] PublicExponentBytes {
			get {
				byte[] bytes = new byte[PublicExponent.Bytes];
				PublicExponent.ToBytes(bytes);
				return bytes;
			}

			set {
				PublicExponent = BigNumber.FromArray(value);
			}
		}
	}
}

