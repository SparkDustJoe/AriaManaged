#pragma once

#include "AriaManaged.h"
using namespace System;
#if _DEBUG
using namespace System::Diagnostics;
#endif
namespace AriaManaged
{
	
#if _DEBUG
	void ARIA::SubL1(_128asBytes^ x)
#else
	inline void ARIA::SubL1(_128asBytes^ x)
#endif
	{
		x[0] = SBox1[x[0]];		x[1] = SBox2[x[1]];		x[2] = SBoxInv1[x[2]];		x[3] = SBoxInv2[x[3]];
		x[4] = SBox1[x[4]];		x[5] = SBox2[x[5]];		x[6] = SBoxInv1[x[6]];		x[7] = SBoxInv2[x[7]];
		x[8] = SBox1[x[8]];		x[9] = SBox2[x[9]];		x[10] = SBoxInv1[x[10]];	x[11] = SBoxInv2[x[11]];
		x[12] = SBox1[x[12]];	x[13] = SBox2[x[13]];	x[14] = SBoxInv1[x[14]];	x[15] = SBoxInv2[x[15]];
	}
#if _DEBUG
	void ARIA::SubL2(_128asBytes^ x)
#else
	inline void ARIA::SubL2(_128asBytes^ x)
#endif
	{
		x[0] = SBoxInv1[x[0]];		x[1] = SBoxInv2[x[1]];		x[2] = SBox1[x[2]];		x[3] = SBox2[x[3]];
		x[4] = SBoxInv1[x[4]];		x[5] = SBoxInv2[x[5]];		x[6] = SBox1[x[6]];		x[7] = SBox2[x[7]];
		x[8] = SBoxInv1[x[8]];		x[9] = SBoxInv2[x[9]];		x[10] = SBox1[x[10]];	x[11] = SBox2[x[11]];
		x[12] = SBoxInv1[x[12]];	x[13] = SBoxInv2[x[13]];	x[14] = SBox1[x[14]];	x[15] = SBox2[x[15]];
	}

	// the scratchpad variables are used to prevent lots of memory allocation (speed and efficiency)

	ARIA::_128asBytes^ ARIA::A(_128asBytes^ data)
	{
		// involute diffusion layer
		array<Byte>^ scratchpad = (array<Byte>^)data->bytes->Clone();
		data[0] = (Byte)(scratchpad[3] ^ scratchpad[4] ^ scratchpad[6] ^ scratchpad[8] ^ scratchpad[9] ^ scratchpad[13] ^ scratchpad[14]);
		data[1] = (Byte)(scratchpad[2] ^ scratchpad[5] ^ scratchpad[7] ^ scratchpad[8] ^ scratchpad[9] ^ scratchpad[12] ^ scratchpad[15]);
		data[2] = (Byte)(scratchpad[1] ^ scratchpad[4] ^ scratchpad[6] ^ scratchpad[10] ^ scratchpad[11] ^ scratchpad[12] ^ scratchpad[15]);
		data[3] = (Byte)(scratchpad[0] ^ scratchpad[5] ^ scratchpad[7] ^ scratchpad[10] ^ scratchpad[11] ^ scratchpad[13] ^ scratchpad[14]);
		data[4] = (Byte)(scratchpad[0] ^ scratchpad[2] ^ scratchpad[5] ^ scratchpad[8] ^ scratchpad[11] ^ scratchpad[14] ^ scratchpad[15]);
		data[5] = (Byte)(scratchpad[1] ^ scratchpad[3] ^ scratchpad[4] ^ scratchpad[9] ^ scratchpad[10] ^ scratchpad[14] ^ scratchpad[15]);
		data[6] = (Byte)(scratchpad[0] ^ scratchpad[2] ^ scratchpad[7] ^ scratchpad[9] ^ scratchpad[10] ^ scratchpad[12] ^ scratchpad[13]);
		data[7] = (Byte)(scratchpad[1] ^ scratchpad[3] ^ scratchpad[6] ^ scratchpad[8] ^ scratchpad[11] ^ scratchpad[12] ^ scratchpad[13]);
		data[8] = (Byte)(scratchpad[0] ^ scratchpad[1] ^ scratchpad[4] ^ scratchpad[7] ^ scratchpad[10] ^ scratchpad[13] ^ scratchpad[15]);
		data[9] = (Byte)(scratchpad[0] ^ scratchpad[1] ^ scratchpad[5] ^ scratchpad[6] ^ scratchpad[11] ^ scratchpad[12] ^ scratchpad[14]);
		data[10] = (Byte)(scratchpad[2] ^ scratchpad[3] ^ scratchpad[5] ^ scratchpad[6] ^ scratchpad[8] ^ scratchpad[13] ^ scratchpad[15]);
		data[11] = (Byte)(scratchpad[2] ^ scratchpad[3] ^ scratchpad[4] ^ scratchpad[7] ^ scratchpad[9] ^ scratchpad[12] ^ scratchpad[14]);
		data[12] = (Byte)(scratchpad[1] ^ scratchpad[2] ^ scratchpad[6] ^ scratchpad[7] ^ scratchpad[9] ^ scratchpad[11] ^ scratchpad[12]);
		data[13] = (Byte)(scratchpad[0] ^ scratchpad[3] ^ scratchpad[6] ^ scratchpad[7] ^ scratchpad[8] ^ scratchpad[10] ^ scratchpad[13]);
		data[14] = (Byte)(scratchpad[0] ^ scratchpad[3] ^ scratchpad[4] ^ scratchpad[5] ^ scratchpad[9] ^ scratchpad[11] ^ scratchpad[14]);
		data[15] = (Byte)(scratchpad[1] ^ scratchpad[2] ^ scratchpad[4] ^ scratchpad[5] ^ scratchpad[8] ^ scratchpad[10] ^ scratchpad[15]);
		scratchpad = nullptr;
		return data;
	}

	// scratchpad prevents needless memory allocation; encrypting = true, normal keying; false, decrypt keying
	ARIA::_key_material^ ARIA::init_key(array<const Byte>^ key, _128asBytes^ scratchpad, bool encrypting)
	{
		if (key == nullptr)
			throw gcnew ArgumentNullException("key");
		if (key->Length != 16 && key->Length != 24 && key->Length != 32)
			throw gcnew ArgumentOutOfRangeException("key", "Key must 128-, 192-, or 256-bit (16, 24, or 32 bytes respectively)");

		_128asBytes^ KR = gcnew _128asBytes(); // right-most bits of key if > 128, else 0
		_128asBytes^ W0 = gcnew _128asBytes(key, 0); // grab the lefthand 128 bits (there will always at least be 128)
		_128asBytes^ W1 = gcnew _128asBytes();
		_128asBytes^ W2 = gcnew _128asBytes();
		_128asBytes^ W3 = gcnew _128asBytes();
		_key_material^ km = gcnew _key_material(key->Length * 8); 
		
		// the A(data, scratchpad) method will copy "data" overwriting "scratchpad", and then update "data" 
		// ("scratchpad" becomes what "data" USED to be before the method call)
		// and then return "data" pointer
		_128asBytes^ CK1; _128asBytes^ CK2;  _128asBytes^ CK3;
		switch (km->keySize)
		{
		case 128: 
			CK1 = const_cast<_128asBytes^>(C1);	CK2 = const_cast<_128asBytes^>(C2);	CK3 = const_cast<_128asBytes^>(C3);
			break;
		case 192:
			CK1 = const_cast<_128asBytes^>(C2);	CK2 = const_cast<_128asBytes^>(C3);	CK3 = const_cast<_128asBytes^>(C1);
			Buffer::BlockCopy(key, 16, KR->bytes, 0, 8);
			break;
		case 256:
			CK1 = const_cast<_128asBytes^>(C3);	CK2 = const_cast<_128asBytes^>(C1);	CK3 = const_cast<_128asBytes^>(C2);
			Buffer::BlockCopy(key, 16, KR->bytes, 0, 16);
			break;
		default: break;
		}

		scratchpad = W0 ^ CK1;
		SubL1(scratchpad);
		W1 = A(scratchpad);
		W1 ^= KR;
			
		scratchpad = W1 ^ CK2;
		SubL2(scratchpad);
		W2 = A(scratchpad);
		W2 ^= W0;

		scratchpad = W2 ^ CK3;
		SubL1(scratchpad);
		W3 = A(scratchpad);
		W3 ^= W1;

		CK1 = nullptr; CK2 = nullptr; CK3 = nullptr; // cleanup
		
#if _DEBUG
		Debug::Print("W0: " + W0->ToString());	Debug::Print("W1: " + W1->ToString());
		Debug::Print("W2: " + W2->ToString());	Debug::Print("W3: " + W3->ToString());
#endif
		KR = nullptr; // cleanup
		km->ek[0] = W0 ^ _128asBytes::RotR(W1, 19);
		km->ek[1] = W1 ^ _128asBytes::RotR(W2, 19);
		km->ek[2] = W2 ^ _128asBytes::RotR(W3, 19);
		km->ek[3] = W3 ^ _128asBytes::RotR(W0, 19);
		km->ek[4] = W0 ^ _128asBytes::RotR(W1, 31);
		km->ek[5] = W1 ^ _128asBytes::RotR(W2, 31);
		km->ek[6] = W2 ^ _128asBytes::RotR(W3, 31);
		km->ek[7] = W3 ^ _128asBytes::RotR(W0, 31);
		km->ek[8] = W0 ^ _128asBytes::RotL(W1, 61);
		km->ek[9] = W1 ^ _128asBytes::RotL(W2, 61);
		km->ek[10] = W2 ^ _128asBytes::RotL(W3, 61);
		km->ek[11] = W3 ^ _128asBytes::RotL(W0, 61);
		km->ek[12] = W0 ^ _128asBytes::RotL(W1, 31);
		if (km->keySize > 128) // add additional rounds
		{
			km->ek[13] = W1 ^ _128asBytes::RotL(W2, 31);
			km->ek[14] = W2 ^ _128asBytes::RotL(W3, 31);
		}
		if (km->keySize > 192) // add additional rounds
		{
			km->ek[15] = W3 ^ _128asBytes::RotL(W0, 31);
			km->ek[16] = W0 ^ _128asBytes::RotL(W1, 19);
		}
		// check for decryption and reverse keys (add involute diffusion A where appropriate)
		if (!encrypting)
		{
			Array::Reverse(km->ek);
			for (short i = km->ek->GetLowerBound(0) + 1; 
				i < km->ek->GetUpperBound(0);
				i++) // do not process first or last in decryption
			{
				A(km->ek[i]);
			}
		}
		W0 = W1 = W2 = W3 = nullptr; // cleanup
#if _DEBUG
		for (short i = 0; i <= km->ek->GetUpperBound(0); i++)
		{
			String^ round = ((i + 1).ToString() + ":")->PadRight(4);
			Debug::Print("ek" + round + (km->ek[i])->ToString());
		}
#endif		
		return km;
	}

	array<Byte>^ ARIA::_proc_block(array<const Byte>^ data, array<const Byte>^ key, bool encrypting)
	{
		if (data == nullptr) throw gcnew ArgumentNullException("data", "must provide data to encrypt/decrypt");
		if (data->Length != 16) throw gcnew ArgumentOutOfRangeException("data", "data not correctly sized (not 128bits)");
		_128asBytes^ scratchpad = gcnew _128asBytes();
		_key_material^ km = ARIA::init_key(key, scratchpad, encrypting); // exception thrown here if key is not right length or null
		_128asBytes^ P = gcnew _128asBytes(data, 0); // plaintext
		array<Byte>^ C;
		// rounds here are zero indexed, so ODD and EVEN here look a little wrong, but the keys are also zero indexed
#if _DEBUG
		Debug::Print("Rounds = " + km->roundCount + " km->ek->Length = " + km->ek->Length);
#endif
		for (int round = 0; round < km->roundCount - 2; round += 2)
		{
			// FO
			P ^= km->ek[round];	SubL1(P); A(P);
#if _DEBUG
			Debug::Print("P" + (round + 1) + "=" + P->ToString());
#endif
			// FE
			P ^= km->ek[round + 1]; SubL2(P); A(P);
#if _DEBUG
			Debug::Print("P" + (round + 2) + "=" + P->ToString());
#endif
		}
		// one last FO
		int finalRounds = km->roundCount - 2;
		P ^= km->ek[finalRounds++];
		SubL1(P);
		A(P);
#if _DEBUG
		Debug::Print("P" + (finalRounds) + "=" + P->ToString());
#endif
		// final round (11, 13, or 15), there will be 1 more key than the number of rounds
		P ^= km->ek[finalRounds++];
		SubL2(P);
		P ^= km->ek[finalRounds]; // final key, 13, 15, or 17
#if _DEBUG
		Debug::Print("OUTPUT=" + P->ToString());
#endif
		km = nullptr; scratchpad = nullptr; // clean-up
		P->CopyTo(C);
		System::Threading::Thread::MemoryBarrier();
		P = nullptr; // more clean-up
		return C;
	}
	
	array<Byte>^ ARIA::EncryptBlock(array<const Byte>^ data, array<const Byte>^ key)
	{
		return _proc_block(data, key, true);
	}

	array<Byte>^ ARIA::DecryptBlock(array<const Byte>^ data, array<const Byte>^ key)
	{
		return _proc_block(data, key, false);
	}
}
