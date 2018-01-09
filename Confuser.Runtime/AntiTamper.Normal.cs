using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Confuser.Runtime
{
	internal static class AntiTamperNormal
    {
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        /// <summary>
        /// Probably decrypts method declarations in memory after they were 
        /// loaded from the PE table?
        /// </summary>
		static unsafe void Initialize()
        {

			Module myMod = typeof(AntiTamperNormal).Module;
			string name = myMod.FullyQualifiedName;
			bool n = name.Length > 0 && name[0] == '<'; //module is special in some kind of way. Loaded from memory? netmodule?

            //memory magic to find addresses
            //see: https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
            var modBase = (byte*)Marshal.GetHINSTANCE(myMod);   //find where the module is loaded in memory
			byte* peData = modBase + *(uint*)(modBase + 0x3c);
			ushort noSections = *(ushort*)(peData + 0x6);
			ushort optSize = *(ushort*)(peData + 0x14);


			uint* dataPtr = null;
			uint encSize = 0;
			var secTable = (uint*)(peData + 0x18 + optSize);
			uint mut1 = (uint)Mutation.KeyI1, mut2 = (uint)Mutation.KeyI2, mut3 = (uint)Mutation.KeyI3, mut4 = (uint)Mutation.KeyI4;
			for (int i = 0; i < noSections; i++) {
				uint g = (*secTable++) * (*secTable++);

				if (g == (uint)Mutation.KeyI0) {
					dataPtr = (uint*)(modBase + (n ? *(secTable + 3) : *(secTable + 1)));
					encSize = (n ? *(secTable + 2) : *(secTable + 0)) >> 2;
				}
				else if (g != 0) {
					var data = (uint*)(modBase + (n ? *(secTable + 3) : *(secTable + 1)));
					uint size = *(secTable + 2) >> 2;
					for (uint k = 0; k < size; k++) {
						uint tmp = (mut1 ^ (*data++)) + mut2 + mut3 * mut4;
						mut1 = mut2;
						mut2 = mut3;    //unused
						mut2 = mut4;
						mut4 = tmp;
					}
				}
				secTable += 8;
			}

            //DeriveKey
			uint[] key = new uint[0x10], cryptKey = new uint[0x10];
			for (int i = 0; i < 0x10; i++) {
				key[i] = mut4;
				cryptKey[i] = mut2;

                //shift the bytes around
				mut1 = (mut2 >> 5) | (mut2 << 27);
				mut2 = (mut3 >> 3) | (mut3 << 29);
				mut3 = (mut4 >> 7) | (mut4 << 25);
				mut4 = (mut1 >> 11) | (mut1 << 21);
			}
			Mutation.Crypt(key, cryptKey);

            //unprotect
			uint prot = 0x40;  //x/r/w
			VirtualProtect((IntPtr)dataPtr, encSize << 2, prot, out prot);

			if (prot == 0x40)   //if it already was xrw, don't decrypt
				return;         //it means that the code was already executable (?)

            //do actual decrypting
			uint xorKeyIndex = 0;
			for (uint i = 0; i < encSize; i++) {
				*dataPtr ^= key[xorKeyIndex & 0xf];
				key[xorKeyIndex & 0xf] = (key[xorKeyIndex & 0xf] ^ (*dataPtr++)) + 0x3dbb2819;
				xorKeyIndex++;
			}
		}
	}
}