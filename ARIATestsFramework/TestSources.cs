﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ARIATestsFramework
{
    public class TestSources
    {
        public EncryptionTests.TestBank Bank128 = new EncryptionTests.TestBank();
        public EncryptionTests.TestBank Bank192 = new EncryptionTests.TestBank();
        public EncryptionTests.TestBank Bank256 = new EncryptionTests.TestBank();
        public TestSources()
        {
            Bank128.Data = new EncryptionTests.Test[10];
            //==================================================================
            Bank128.Key = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            //======================================
            Bank128.Data[0].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank128.Data[1].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xcc, 0xcc, 0xcc, 0xcc, 0x11, 0x11, 0x11, 0x11, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank128.Data[2].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xaa, 0xaa, 0xaa, 0xaa, 0x22, 0x22, 0x22, 0x22, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank128.Data[3].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xcc, 0xcc, 0xcc, 0xcc, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank128.Data[4].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xaa, 0xaa, 0xaa, 0xaa, 0x33, 0x33, 0x33, 0x33, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank128.Data[5].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xcc, 0x33, 0x33, 0x33, 0x33, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank128.Data[6].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xaa, 0xaa, 0xaa, 0xaa, 0x44, 0x44, 0x44, 0x44, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank128.Data[7].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xcc, 0xcc, 0xcc, 0xcc, 0x44, 0x44, 0x44, 0x44, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank128.Data[8].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x55, 0x55, 0x55, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank128.Data[9].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x55, 0x55, 0x55, 0xdd, 0xdd, 0xdd, 0xdd };

            Bank128.Data[0].C = new byte[] { 0xc6, 0xec, 0xd0, 0x8e, 0x22, 0xc3, 0x0a, 0xbd, 0xb2, 0x15, 0xcf, 0x74, 0xe2, 0x07, 0x5e, 0x6e };
            Bank128.Data[1].C = new byte[] { 0x29, 0xcc, 0xaa, 0xc6, 0x34, 0x48, 0x70, 0x8d, 0x33, 0x1b, 0x2f, 0x81, 0x6c, 0x51, 0xb1, 0x7d };
            Bank128.Data[2].C = new byte[] { 0x9e, 0x13, 0x3d, 0x15, 0x28, 0xdb, 0xf0, 0xaf, 0x57, 0x87, 0xc7, 0xf3, 0xa3, 0xf5, 0xc2, 0xbf };
            Bank128.Data[3].C = new byte[] { 0x6b, 0x6f, 0x34, 0x59, 0x07, 0xa3, 0x05, 0x56, 0x12, 0xce, 0x07, 0x2f, 0xf5, 0x4d, 0xe7, 0xd7 };
            Bank128.Data[4].C = new byte[] { 0x88, 0x42, 0x4d, 0xa6, 0xe8, 0xcc, 0xfe, 0x81, 0x72, 0xb3, 0x91, 0xbe, 0x49, 0x93, 0x54, 0x16 };
            Bank128.Data[5].C = new byte[] { 0x56, 0x65, 0xba, 0x78, 0x64, 0x91, 0x70, 0x00, 0xa6, 0xee, 0xb2, 0xec, 0xb4, 0xa6, 0x98, 0xed };
            Bank128.Data[6].C = new byte[] { 0xfc, 0x78, 0x87, 0xe7, 0xf5, 0x56, 0x37, 0x76, 0x14, 0xab, 0x0a, 0x28, 0x22, 0x93, 0xe6, 0xd8 };
            Bank128.Data[7].C = new byte[] { 0x84, 0xdb, 0xb8, 0x42, 0x06, 0xcd, 0xb1, 0x6e, 0xd1, 0x75, 0x4e, 0x77, 0xa1, 0xf2, 0x43, 0xfd };
            Bank128.Data[8].C = new byte[] { 0x08, 0x69, 0x53, 0xf7, 0x52, 0xcc, 0x1e, 0x46, 0xc7, 0xc7, 0x94, 0xae, 0x85, 0x53, 0x7d, 0xca };
            Bank128.Data[9].C = new byte[] { 0xec, 0x8d, 0xd7, 0x21, 0xf5, 0x5c, 0x93, 0xb6, 0xed, 0xfe, 0x2a, 0xde, 0xa4, 0x38, 0x73, 0xe8 };

            Bank192.Data = new EncryptionTests.Test[10];
            //==================================================================
            Bank192.Key = new byte[24] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
            //======================================
            Bank192.Data[0].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank192.Data[1].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xcc, 0xcc, 0xcc, 0xcc, 0x11, 0x11, 0x11, 0x11, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank192.Data[2].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xaa, 0xaa, 0xaa, 0xaa, 0x22, 0x22, 0x22, 0x22, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank192.Data[3].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xcc, 0xcc, 0xcc, 0xcc, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank192.Data[4].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xaa, 0xaa, 0xaa, 0xaa, 0x33, 0x33, 0x33, 0x33, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank192.Data[5].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xcc, 0x33, 0x33, 0x33, 0x33, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank192.Data[6].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xaa, 0xaa, 0xaa, 0xaa, 0x44, 0x44, 0x44, 0x44, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank192.Data[7].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xcc, 0xcc, 0xcc, 0xcc, 0x44, 0x44, 0x44, 0x44, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank192.Data[8].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x55, 0x55, 0x55, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank192.Data[9].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x55, 0x55, 0x55, 0xdd, 0xdd, 0xdd, 0xdd };

            Bank192.Data[0].C = new byte[] { 0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac, 0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b };
            Bank192.Data[1].C = new byte[] { 0x5f, 0x23, 0xd3, 0x3b, 0xff, 0x78, 0xf4, 0x6c, 0x3c, 0x15, 0x91, 0x1f, 0x4a, 0x21, 0x80, 0x9a };
            Bank192.Data[2].C = new byte[] { 0xac, 0xca, 0xd8, 0x0b, 0x4b, 0xda, 0x91, 0x5a, 0xa9, 0xda, 0xe6, 0xbc, 0xeb, 0xe0, 0x6a, 0x6c };
            Bank192.Data[3].C = new byte[] { 0x83, 0xf7, 0x7f, 0xd5, 0x39, 0x1a, 0xcf, 0xe6, 0x1d, 0xe2, 0xf6, 0x46, 0xb5, 0xd4, 0x47, 0xed };
            Bank192.Data[4].C = new byte[] { 0xbf, 0xd5, 0xbb, 0x49, 0xb1, 0x2f, 0xbb, 0x91, 0x45, 0xb2, 0x27, 0x89, 0x5a, 0x75, 0x7b, 0x2a };
            Bank192.Data[5].C = new byte[] { 0xf1, 0xf7, 0x18, 0x87, 0x34, 0x86, 0x3d, 0x7b, 0x8b, 0x6e, 0xde, 0x5a, 0x5b, 0x2f, 0x06, 0xa0 };
            Bank192.Data[6].C = new byte[] { 0xa2, 0x33, 0xc8, 0x52, 0x3d, 0x2d, 0xb7, 0x78, 0xfb, 0x31, 0xb0, 0xe3, 0x11, 0xf3, 0x27, 0x00 };
            Bank192.Data[7].C = new byte[] { 0x15, 0x2f, 0x33, 0x86, 0x1e, 0x9d, 0x04, 0x0c, 0x83, 0xb5, 0xeb, 0x40, 0xcd, 0x88, 0xea, 0x49 };
            Bank192.Data[8].C = new byte[] { 0x97, 0x57, 0x09, 0xdc, 0x62, 0x93, 0x65, 0xa1, 0x89, 0xf7, 0x8a, 0x3e, 0xc4, 0x03, 0x45, 0xfc };
            Bank192.Data[9].C = new byte[] { 0x6a, 0x5a, 0x30, 0x7a, 0x8f, 0x9a, 0x44, 0x13, 0x09, 0x1e, 0x00, 0x7e, 0xca, 0x56, 0x45, 0xa0 };

            Bank256.Data = new EncryptionTests.Test[10];
            //==================================================================
            Bank256.Key = new byte[32] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            //======================================
            Bank256.Data[0].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank256.Data[1].P = new byte[] { 0x11, 0x11, 0x11, 0x11, 0xcc, 0xcc, 0xcc, 0xcc, 0x11, 0x11, 0x11, 0x11, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank256.Data[2].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xaa, 0xaa, 0xaa, 0xaa, 0x22, 0x22, 0x22, 0x22, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank256.Data[3].P = new byte[] { 0x22, 0x22, 0x22, 0x22, 0xcc, 0xcc, 0xcc, 0xcc, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank256.Data[4].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xaa, 0xaa, 0xaa, 0xaa, 0x33, 0x33, 0x33, 0x33, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank256.Data[5].P = new byte[] { 0x33, 0x33, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xcc, 0x33, 0x33, 0x33, 0x33, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank256.Data[6].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xaa, 0xaa, 0xaa, 0xaa, 0x44, 0x44, 0x44, 0x44, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank256.Data[7].P = new byte[] { 0x44, 0x44, 0x44, 0x44, 0xcc, 0xcc, 0xcc, 0xcc, 0x44, 0x44, 0x44, 0x44, 0xdd, 0xdd, 0xdd, 0xdd };
            Bank256.Data[8].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x55, 0x55, 0x55, 0xbb, 0xbb, 0xbb, 0xbb };
            Bank256.Data[9].P = new byte[] { 0x55, 0x55, 0x55, 0x55, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x55, 0x55, 0x55, 0xdd, 0xdd, 0xdd, 0xdd };

            Bank256.Data[0].C = new byte[] { 0x58, 0xa8, 0x75, 0xe6, 0x04, 0x4a, 0xd7, 0xff, 0xfa, 0x4f, 0x58, 0x42, 0x0f, 0x7f, 0x44, 0x2d };
            Bank256.Data[1].C = new byte[] { 0x8e, 0x19, 0x10, 0x16, 0xf2, 0x8e, 0x79, 0xae, 0xfc, 0x01, 0xe2, 0x04, 0x77, 0x32, 0x80, 0xd7 };
            Bank256.Data[2].C = new byte[] { 0x01, 0x8e, 0x5f, 0x7a, 0x93, 0x8e, 0xc3, 0x07, 0x11, 0x71, 0x99, 0x53, 0xba, 0xe8, 0x65, 0x42 };
            Bank256.Data[3].C = new byte[] { 0xcd, 0x7e, 0xbc, 0x75, 0x24, 0x74, 0xc1, 0xa5, 0xf6, 0xea, 0xaa, 0xce, 0x2a, 0x7e, 0x29, 0x46 };
            Bank256.Data[4].C = new byte[] { 0x2e, 0xe7, 0xdf, 0xa5, 0xaf, 0xdb, 0x84, 0x17, 0x7e, 0xad, 0x95, 0xcc, 0xd4, 0xb4, 0xbb, 0x6e };
            Bank256.Data[5].C = new byte[] { 0x1e, 0xd1, 0x7b, 0x95, 0x34, 0xcf, 0xf0, 0xa5, 0xfc, 0x29, 0x41, 0x42, 0x9c, 0xfe, 0xe2, 0xee };
            Bank256.Data[6].C = new byte[] { 0x49, 0xc7, 0xad, 0xbe, 0xb7, 0xe9, 0xd1, 0xb0, 0xd2, 0xa8, 0x53, 0x1d, 0x94, 0x20, 0x79, 0x59 };
            Bank256.Data[7].C = new byte[] { 0x6a, 0x27, 0xed, 0x79, 0xf5, 0xb1, 0xdd, 0x13, 0xec, 0xd6, 0x04, 0xb0, 0x7a, 0x48, 0x88, 0x5a };
            Bank256.Data[8].C = new byte[] { 0x3a, 0xfa, 0x06, 0x27, 0xa0, 0xe4, 0xe6, 0x0a, 0x3c, 0x70, 0x3a, 0xf2, 0x92, 0xf1, 0xba, 0xa7 };
            Bank256.Data[9].C = new byte[] { 0x7b, 0x70, 0x2f, 0x16, 0xc5, 0x4a, 0xa7, 0x4b, 0xc7, 0x27, 0xea, 0x95, 0xc7, 0x46, 0x8b, 0x00 };

        }
    }
}
