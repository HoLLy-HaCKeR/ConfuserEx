using System;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace Confuser.Runtime
{
	internal static class Constant
    {
		static byte[] buffer;

		static void Initialize()
        {
		    const int blockSize = 0x10;

            // initialize encrypted buffer
			uint length = (uint)Mutation.KeyI0;  // encrypted buffer length
			uint[] encryptedBuffer = Mutation.Placeholder(new uint[Mutation.KeyI0]);

            // initialize key
			uint[] key = new uint[blockSize];
			uint n = (uint)Mutation.KeyI1;   // seed
			for (int i = 0; i < blockSize; i++) {
				n ^= n >> 12;
				n ^= n << 25;
				n ^= n >> 27;
				key[i] = n;
			}

            // decrypt the buffer
			int index = 0;
			uint[] tempBuffer = new uint[blockSize];
			byte[] compressedBuffer = new byte[length * 4];

			for (int offset = 0; offset < length; offset += blockSize)
            {
                // copy block to temp buffer
				for (int i = 0; i < blockSize; i++)
					tempBuffer[i] = encryptedBuffer[offset + i];

                // decrypt buffer with key
				Mutation.Crypt(tempBuffer, key);

                // copy uint to compressed buffer, and update key
				for (int i = 0; i < blockSize; i++) {
					uint e = tempBuffer[i];
					compressedBuffer[index++] = (byte)(e >> (8 * 0));
					compressedBuffer[index++] = (byte)(e >> (8 * 1));
					compressedBuffer[index++] = (byte)(e >> (8 * 2));
					compressedBuffer[index++] = (byte)(e >> (8 * 3));
					key[i] ^= e;
				}
			}

            // decompress the buffer
			buffer = Lzma.Decompress(compressedBuffer);
		}

		static T Get<T>(uint id)
        {
		    T ret = default(T);

            // prevent string decryptors from invoking this method
            if (!Equals(Assembly.GetCallingAssembly(), Assembly.GetExecutingAssembly())
                || new StackTrace().GetFrame(1).GetMethod().DeclaringType == typeof(RuntimeMethodHandle))
		        return ret;

            // demutate the id
			id = (uint)Mutation.Placeholder((int)id);

            // get the type
			uint type = id >> 30;

            // get actual id
			id &= 0x3fffffff;
			id <<= 2;

			if (type == Mutation.KeyI0) {
                // read a string preceded by a 32bit length int
				int len = buffer[id++] | (buffer[id++] << 8) | (buffer[id++] << 16) | (buffer[id++] << 24);
				ret = (T)(object)string.Intern(Encoding.UTF8.GetString(buffer, (int)id, len));
			}
			// NOTE: Assume little-endian
			else if (type == Mutation.KeyI1) {
                //read an int
				var v = new T[1];
				Buffer.BlockCopy(buffer, (int)id, v, 0, Mutation.Value<int>());
				ret = v[0];
			}
			else if (type == Mutation.KeyI2) {
                // read an array
				int structLength = buffer[id++] | (buffer[id++] << 8) | (buffer[id++] << 16) | (buffer[id++] << 24);
				int arrayLength = buffer[id++] | (buffer[id++] << 8) | (buffer[id++] << 16) | (buffer[id++] << 24);
				Array v = Array.CreateInstance(typeof(T).GetElementType(), arrayLength);
				Buffer.BlockCopy(buffer, (int)id, v, 0, structLength - 4);
				ret = (T)(object)v;
			}
			return ret;
		}
	}

	internal struct CFGCtx
    {
		uint A;
		uint B;
		uint C;
		uint D;

		public CFGCtx(uint seed)
        {
			A = seed *= 0x21412321;
			B = seed *= 0x21412321;
			C = seed *= 0x21412321;
			D = seed *= 0x21412321;
		}

		public uint Next(byte f, uint q)
        {
			if ((f & 0b1000_0000) != 0) {   // if MSB in f is set
				switch (f & 0b0011) {
					case 0: A = q; break;
					case 1: B = q; break;
					case 2: C = q; break;
					case 3: D = q; break;
				}
			}
			else {
				switch (f & 0b0011) {
					case 0: A ^= q; break;
					case 1: B += q; break;
					case 2: C ^= q; break;
					case 3: D -= q; break;
				}
			}

			switch ((f >> 2) & 0b0011) {
				case 0: return A;
				case 1: return B;
				case 2: return C;
                default: return D;
			}
		}
	}
}