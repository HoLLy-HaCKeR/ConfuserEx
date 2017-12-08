using System;
using System.Reflection;

namespace Confuser.Runtime
{
	internal static class Resource
    {
		static Assembly assembly;
        
		static void Initialize()    // very similar to constants encryption initialization
        {
		    const int blockSize = 0x10;

            // initialize encrypted buffer
			uint length = (uint)Mutation.KeyI0;  // encrypted buffer length
            uint[] encryptedBuffer = Mutation.Placeholder(new uint[Mutation.KeyI0]);

            // initialize key
			uint[] key = new uint[blockSize];
			uint n = (uint)Mutation.KeyI1;  // seed
			for (int i = 0; i < blockSize; i++) {
				n ^= n >> 13;
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

            //decompress the assembly
			assembly = Assembly.Load(Lzma.Decompress(compressedBuffer));
			AppDomain.CurrentDomain.AssemblyResolve += Handler;
		}

		static Assembly Handler(object sender, ResolveEventArgs args) => assembly.FullName == args.Name ? assembly : null;
    }

	internal static class Resource_Packer
    {
		static Assembly assembly;

		// Hmm... Too lazy.
		static void Initialize()
        {
		    const int blockSize = 0x10;

		    // initialize encrypted buffer
		    uint length = (uint)Mutation.KeyI0;  // encrypted buffer length
		    uint[] encryptedBuffer = Mutation.Placeholder(new uint[Mutation.KeyI0]);

		    // initialize key
		    uint[] key = new uint[blockSize];
		    uint n = (uint)Mutation.KeyI1;  // seed
		    for (int i = 0; i < blockSize; i++)
		    {
		        n ^= n >> 13;
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
		        for (int i = 0; i < blockSize; i++)
		        {
		            uint e = tempBuffer[i];
		            compressedBuffer[index++] = (byte)(e >> (8 * 0));
		            compressedBuffer[index++] = (byte)(e >> (8 * 1));
		            compressedBuffer[index++] = (byte)(e >> (8 * 2));
		            compressedBuffer[index++] = (byte)(e >> (8 * 3));
		            key[i] ^= e;
		        }
		    }

            assembly = Assembly.Load(Lzma.Decompress(compressedBuffer));
			AppDomain.CurrentDomain.ResourceResolve += Handler;
		}

		static Assembly Handler(object sender, ResolveEventArgs args)
		{
		    string[] n = assembly.GetManifestResourceNames();
			return Array.IndexOf(n, args.Name) != -1 ? assembly : null;
		}
	}
}