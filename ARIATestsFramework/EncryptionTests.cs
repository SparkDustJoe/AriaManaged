using AriaManaged;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace ARIATestsFramework
{
    [TestClass]
    public class EncryptionTests
    {
        public struct Test
        {
            public byte[] P; // Plaintext
            public byte[] C; // expected Ciphertext
        }

        public struct TestBank
        {
            public byte[] Key;
            public Test[] Data;
        }

#if DEBUG
        [TestMethod]
        public void SelfTest()
        {
            Assert.IsTrue(AriaManaged.ARIA.RunSelfTests());
        }
#endif

        // test vectors taken from RFC 5794 and from https://github.com/weidai11/cryptopp/blob/master/TestVectors/aria.txt
        // the source document listed at above address mentions ARIA Test Vectors PDF (05.05.2004) but I was not able to locate that source
        // the document includes CBC and CTR vectors as well, so maybe another RFC for ARIA in TLS/SSL??
        TestSources ts = new TestSources();

        [TestMethod]
        public void EncryptIntermediate128BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] K = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            byte[] result = ARIA.EncryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73, 0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78 }, 
                out int FirstDiff), "RFC Encrypt 128 Test Failed");

            //pdf
            K = ts.Bank128.Key;
            foreach (Test t in ts.Bank128.Data)
            {
                result = ARIA.EncryptBlock(t.P, K);
                Assert.IsTrue(compareArrays(result, t.C, out FirstDiff), "PDF Encrypt 128 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }

        [TestMethod]
        public void DecryptIntermediate128BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73, 0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78 };
            byte[] K = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            byte[] result = ARIA.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 
                out int FirstDiff), "RFC Decrypt 128 Test Failed");

            //pdf
            K = ts.Bank128.Key;
            foreach (Test t in ts.Bank128.Data)
            {
                result = ARIA.DecryptBlock(t.C, K);
                Assert.IsTrue(compareArrays(result, t.P, out FirstDiff), "PDF Decrypt 128 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }

        [TestMethod]
        public void EncryptIntermediate192BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] K = new byte[24] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
            byte[] result = ARIA.EncryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x26, 0x44, 0x9c, 0x18, 0x05, 0xdb, 0xe7, 0xaa, 0x25, 0xa4, 0x68, 0xce, 0x26, 0x3a, 0x9e, 0x79 }, 
                out int FirstDiff), "RFC Encrypt 192 Test Failed");

            //pdf
            K = ts.Bank192.Key;
            foreach (Test t in ts.Bank192.Data)
            {
                result = ARIA.EncryptBlock(t.P, K);
                Assert.IsTrue(compareArrays(result, t.C, out FirstDiff), "PDF Encrypt 192 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }

        [TestMethod]
        public void DecryptIntermediate192BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0x26, 0x44, 0x9c, 0x18, 0x05, 0xdb, 0xe7, 0xaa, 0x25, 0xa4, 0x68, 0xce, 0x26, 0x3a, 0x9e, 0x79 };
            byte[] K = new byte[24] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
            byte[] result = ARIA.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 
                out int FirstDiff), "RFC Decrypt 192 Test Failed");

            //pdf
            K = ts.Bank192.Key;
            foreach (Test t in ts.Bank192.Data)
            {
                result = ARIA.DecryptBlock(t.C, K);
                Assert.IsTrue(compareArrays(result, t.P, out FirstDiff), "PDF Decrypt 192 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }

        [TestMethod]
        public void EncryptIntermediate256BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] K = new byte[32] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
            byte[] result = ARIA.EncryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f, 0x2b, 0x8f, 0x80, 0xc1, 0x97, 0x2d, 0x24, 0xfc }, 
                out int FirstDiff), "RFC Encrypt 256 Test Failed");

            //pdf
            K = ts.Bank256.Key;
            foreach (Test t in ts.Bank256.Data)
            {
                result = ARIA.EncryptBlock(t.P, K);
                Assert.IsTrue(compareArrays(result, t.C, out FirstDiff), "PDF Encrypt 256 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }

        [TestMethod]
        public void DecryptIntermediate256BitKeys()
        {
            //rfc
            byte[] P = new byte[16] { 0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f, 0x2b, 0x8f, 0x80, 0xc1, 0x97, 0x2d, 0x24, 0xfc };
            byte[] K = new byte[32] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
            byte[] result = ARIA.DecryptBlock(P, K);
            Assert.IsTrue(compareArrays(result,
                new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 
                out int FirstDiff), "RFC Decrypt 256 Test Failed");

            //pdf
            K = ts.Bank256.Key;
            foreach (Test t in ts.Bank256.Data)
            {
                result = ARIA.DecryptBlock(t.C, K);
                Assert.IsTrue(compareArrays(result, t.P, out FirstDiff), "PDF Decrypt 256 Test Source Failed: " + t.C[0].ToString("x2"));
            }
        }
        

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_NullData()
        {
            ARIA.EncryptBlock(null, new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_InvalidDataLength()
        {
            ARIA.EncryptBlock(new byte[3], new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_NullKey()
        {
            ARIA.EncryptBlock(new byte[16], null);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Encrypt_Exception_InvalidKeyLength()
        {
            ARIA.EncryptBlock(new byte[16], new byte[1]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_NullData()
        {
            ARIA.DecryptBlock(null, new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_InvalidDataLength()
        {
            ARIA.DecryptBlock(new byte[3], new byte[16]);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentNullException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_NullKey()
        {
            ARIA.DecryptBlock(new byte[16], null);
            Assert.Fail("Did not throw exception");
        }

        [TestMethod]
        [ExpectedException(exceptionType: typeof(ArgumentOutOfRangeException), AllowDerivedTypes = true)]
        public void Decrypt_Exception_InvalidKeyLength()
        {
            ARIA.DecryptBlock(new byte[16], new byte[1]);
            Assert.Fail("Did not throw exception");
        }



        private static bool compareArrays(byte[] a, byte[] b, out int firstDifference)
        {
            firstDifference = -1;
            if (a.Length != b.Length)
            {
                firstDifference = (int)Math.Min(a.Length, b.Length);
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    firstDifference = i;
                    return false;
                }
            }
            return true;
        }
    }
}
