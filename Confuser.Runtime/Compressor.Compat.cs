using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Confuser.Runtime
{
	internal static class CompressorCompat
    {
		static byte[] sigBlob;

	    static GCHandle Decrypt(uint[] encrypted, uint seed) 
	    {
	        const int blockSize = 0x10;
	        const int blockMask = blockSize - 1;
	        const byte byteMask = 0xff;

	        // load key and iv
	        var iv = new uint[blockSize];
	        var key = new uint[blockSize];
	        ulong s = seed;
	        for (int i = 0; i < blockSize; i++)
	        {
	            // mutate seed
	            s = (s * s) % 0x143fc089;

	            // set in key and buffer
	            key[i] = (uint)s;
	            iv[i] = (uint)((s * s) % 0x444d56fb);
	        }
	        Mutation.Crypt(iv, key);
	        Array.Clear(key, 0, blockSize);

	        //decrypt the buffer
	        var compressedBuffer = new byte[encrypted.Length << 2];
	        uint offset = 0;
	        for (int i = 0; i < encrypted.Length; i++)
	        {
	            // decrypt 4 bytes and update iv
	            uint data = encrypted[i] ^ iv[i & blockMask];
	            iv[i & blockMask] = (iv[i & blockMask] ^ data) + 0x3ddb2819;

	            //add bytes to the compressed buffer
	            compressedBuffer[offset + 0] = (byte)(data >> (8 * 0));
	            compressedBuffer[offset + 1] = (byte)(data >> (8 * 1));
	            compressedBuffer[offset + 2] = (byte)(data >> (8 * 2));
	            compressedBuffer[offset + 3] = (byte)(data >> (8 * 3));
	            offset += 4;
	        }

	        // decompress and clear unused buffers
	        Array.Clear(iv, 0, blockSize);
	        byte[] decompressed = Lzma.Decompress(compressedBuffer);
	        Array.Clear(compressedBuffer, 0, compressedBuffer.Length);

	        // create a gc handle and do final decrypt
	        GCHandle g = GCHandle.Alloc(decompressed, GCHandleType.Pinned);
	        for (int i = 0; i < decompressed.Length; i++)
	        {
	            decompressed[i] ^= (byte)s;
	            if ((i & byteMask) == 0)    //every 256 bytes
	                s = (s * s) % 0x8a5cb7;
	        }
	        return g;
	    }

        [STAThread]
		static int Main(string[] args)
        {
			uint[] encryptedMod = Mutation.Placeholder(new uint[Mutation.KeyI0]);

            // decrypt assembly and free unused resources
			GCHandle handle = Decrypt(encryptedMod, (uint)Mutation.KeyI1);
			var modBytes = (byte[])handle.Target;
			Assembly ass = Assembly.Load(modBytes);
			Array.Clear(modBytes, 0, modBytes.Length);
			handle.Free();
			Array.Clear(encryptedMod, 0, encryptedMod.Length);

            // resolve main method's signature
			var mod = typeof(CompressorCompat).Module;
			sigBlob = mod.ResolveSignature(Mutation.KeyI2);

            // add custom assembly resolver
			AppDomain.CurrentDomain.AssemblyResolve += Resolve;

            // finally get the main method
            MethodBase main = ass.ManifestModule.ResolveMethod(sigBlob[0] | (sigBlob[1] << 8) | (sigBlob[2] << 16) | (sigBlob[3] << 24));

            // invoke the main method with strings[] as parameter, if needed
            var parameters = new object[main.GetParameters().Length];
			if (parameters.Length != 0) parameters[0] = args;
			object ret = main.Invoke(null, parameters);
            return ret is int i ? i : 0;
        }

	    static Assembly Resolve(object sender, ResolveEventArgs e)
        {
	        const int blockSize = 0x100;

	        byte[] resourceNameRaw = Encoding.UTF8.GetBytes(new AssemblyName(e.Name).FullName.ToUpperInvariant());

	        Stream stream = null;

	        // load resource stream
	        if (resourceNameRaw.Length + 4 <= sigBlob.Length)
	        {
	            for (int i = 0; i < resourceNameRaw.Length; i++)
	                resourceNameRaw[i] *= sigBlob[i + 4];
	            string b64 = Convert.ToBase64String(resourceNameRaw);
	            stream = Assembly.GetEntryAssembly().GetManifestResourceStream(b64);
	        }

	        if (stream != null)
	        {
	            var encryptedAssembly = new uint[stream.Length >> 2];

	            // read stream to buffer
	            var block = new byte[blockSize];
	            int amtRead;
	            int dstOffset = 0;
	            while ((amtRead = stream.Read(block, 0, blockSize)) > 0)
	            {
	                Buffer.BlockCopy(block, 0, encryptedAssembly, dstOffset, amtRead);
	                dstOffset += amtRead;
	            }

	            // get a seed/key and decrypt
	            uint s = 0x6fff61;
	            foreach (byte chr in resourceNameRaw)
	                s = s * 0x5e3f1f + chr;
	            GCHandle handle = Decrypt(encryptedAssembly, s);

	            // load assembly and clear buffers
	            var decryptedAss = (byte[])handle.Target;
	            Assembly ass = Assembly.Load(decryptedAss);
	            Array.Clear(decryptedAss, 0, decryptedAss.Length);
	            handle.Free();
	            Array.Clear(encryptedAssembly, 0, encryptedAssembly.Length);

	            return ass;
	        }
	        return null;
	    }
    }
}