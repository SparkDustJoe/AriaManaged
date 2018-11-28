﻿using AriaManaged;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
#if DEBUG
using System.Diagnostics;
#endif
namespace ARIATester
{
    public class Program
    {
        static void Main(string[] args)
        {
            if (ARIA.RunSelfTests())
            {
                Console.WriteLine("SelfTest OK!");
            }
            else
            {
                Console.WriteLine("*** SelfTest FAILED!!! ***");
            }

#if DEBUG
            //Excercise Debug routines
            // Common plaintext
            byte[] P = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            Debug.Print("PT:" + BitConverter.ToString(P).Replace("-", "").ToLower());
            //128-bit key
            Debug.Print("==128-BIT KEY=============================================");
            byte[] K = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            byte[] result = ARIA.EncryptBlock(P, K);
            Debug.Print("CT:" + BitConverter.ToString(result).Replace("-", "").ToLower());
            result = ARIA.DecryptBlock(result, K);
            Debug.Print("PT:" + BitConverter.ToString(result).Replace("-", "").ToLower());

            //192-bit key
            Debug.Print("==192-BIT KEY=============================================");
            K = new byte[24] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
            result = ARIA.EncryptBlock(P, K);
            Debug.Print("CT:" + BitConverter.ToString(result).Replace("-", "").ToLower());
            result = ARIA.DecryptBlock(result, K);
            Debug.Print("PT:" + BitConverter.ToString(result).Replace("-", "").ToLower());

            //256-bit key
            Debug.Print("==256-BIT KEY=============================================");
            K = new byte[32] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
            result = ARIA.EncryptBlock(P, K);
            Debug.Print("CT:" + BitConverter.ToString(result).Replace("-", "").ToLower());
            result = ARIA.DecryptBlock(result, K);
            Debug.Print("PT:" + BitConverter.ToString(result).Replace("-", "").ToLower());
#endif
            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }
    }
}
