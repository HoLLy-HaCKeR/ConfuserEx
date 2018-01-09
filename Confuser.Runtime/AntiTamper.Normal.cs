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
        /// Decrypts PE sections (containing eg. method bodies) in memory
        /// </summary>
		static unsafe void Initialize()
        {
			Module myMod = typeof(AntiTamperNormal).Module;
			string name = myMod.FullyQualifiedName;
			bool notMapped = name.Length > 0 && name[0] == '<';

            //memory magic to find addresses
            //see: https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
            var modBase = (byte*)Marshal.GetHINSTANCE(myMod);   //find where the module is loaded in memory
			byte* peData = modBase + *(uint*)(modBase + 0x3c);  //pointer to the PE header (skips past DOS stub)
			ushort sectNum = *(ushort*)(peData + 0x6);          //amount of sections
			ushort optSize = *(ushort*)(peData + 0x14);         //size of the optional header

            //loop through all sections and do stuff (read comments below)
			uint* encLoc = null;
			uint encSize = 0;
			var secTable = (uint*)(peData + 0x18 + optSize);    //base of the section table
			uint mut1 = (uint)Mutation.KeyI1, mut2 = (uint)Mutation.KeyI2, mut3 = (uint)Mutation.KeyI3, mut4 = (uint)Mutation.KeyI4;
			for (int i = 0; i < sectNum; i++) {
                //Multiply the 2 dwords of the name, move secTable to past the 
                //name. The name is in ascii, so this would only be 0 if the 
                //section name is 4 or less characters long. There is a section
                //with an empty name where various stuff gets moved too and is
                //not handled below.
                uint nameHash = (*secTable++) * (*secTable++);

                //this is the section we added containing MetaData, 
                //NetResources, Constants and method bodies
                if (nameHash == (uint)Mutation.KeyI0) {
					encLoc = (uint*)(modBase + (notMapped 
                        ? *(secTable + 3)       //raw data
                        : *(secTable + 1)));    //virtual address (RVA)
					encSize = (notMapped 
                        ? *(secTable + 2)       //size of raw data
                        : *(secTable + 0)) >> 2;//virtual size
				}
                //normal sections
				else if (nameHash != 0) {
					var data = (uint*)(modBase + (notMapped 
                        ? *(secTable + 3)       //raw data
                        : *(secTable + 1)));    //RVA

					uint size = *(secTable + 2) >> 2;   //section size (in ints)

                    //update key based on this data
					for (uint k = 0; k < size; k++) {
						uint tmp = (mut1 ^ (*data++)) + mut2 + mut3 * mut4;
						mut1 = mut2;
						mut2 = mut3;    //unused
						mut2 = mut4;
						mut4 = tmp;
					}
				}
				secTable += 8;  //skip the rest of the section md and go to the next one
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
			Mutation.Crypt(key, cryptKey);  //executes xor, mul or add on each item with itself, depending on i % 3

            //unprotect
			uint prot = 0x40;  //xrw
			VirtualProtect((IntPtr)encLoc, encSize << 2, prot, out prot);

			if (prot == 0x40)   //if it already was xrw, don't decrypt
				return;         //it means that the code was already executable (?)

            //do actual decrypting over the entire protected area
			uint xorKeyIndex = 0;
			for (uint i = 0; i < encSize; i++) {
                //xor key[i % 16] with the value in memory
				*encLoc ^= key[xorKeyIndex & 0x0F];
                
                //take previous value of encLoc, add constant to it, store that in key
				key[xorKeyIndex & 0xf] = (key[xorKeyIndex & 0xf] ^ (*encLoc++)) + 0x3DBB2819;
				xorKeyIndex++;
			}
		}
	}
}