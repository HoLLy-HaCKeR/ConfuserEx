using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Confuser.Runtime
{
	internal static class AntiDump
    {
		[DllImport("kernel32.dll")]
		static extern unsafe bool VirtualProtect(byte* lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        /// <summary>
        /// Overwrites a bunch of stuff in memory to make the module not look
        /// like a .NET module. Basically.
        /// </summary>
		static unsafe void Initialize()
        {
            //get ptr to PE data
            Module myMod = typeof(AntiDump).Module;
			var modBase = (byte*)Marshal.GetHINSTANCE(myMod);
			byte* ptr = modBase + 0x3c;

            //jump to section table
            ptr = modBase + *(uint*)ptr;
			ptr += 0x6;
			ushort sectNum = *(ushort*)ptr; //amount of sections
			ptr += 0xE;
			ushort optSize = *(ushort*)ptr; //size of optional header
			ptr = ptr + 0x4 + optSize;      //jump to section table

            //
			byte* @new = stackalloc byte[11];
			if (myMod.FullyQualifiedName[0] != '<') //Mapped
			{
				//VirtualProtect(ptr - 16, 8, 0x40, out old);
				//*(uint*)(ptr - 12) = 0;
				byte* mdDir = modBase + *(uint*)(ptr - 0x10); //CLRRuntimeHeader, offset to .cormeta aka #~
                //*(uint*)(ptr - 16) = 0;

                #region overwrite some function to NtContinue in ntdll
                if (*(uint*)(ptr - 0x78) != 0) {    //ImportTable
				    //see: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx#import_directory_table
                    byte* importDir = modBase + *(uint*)(ptr - 0x78);   //offset of import table/directory

					byte* oftMod = modBase + *(uint*)importDir;         //ptr to import table base
					byte* modName = modBase + *(uint*)(importDir + 12); //ptr to name RVA (ascii name of DLL)
					byte* funcName = modBase + *(uint*)oftMod + 2;      //forwarder chain?

                    //write "ntdll.dll\0\0" to module/dll name
                    VirtualProtect(modName, 11, 0x40, out _);
                    *(uint*)@new = 0x6c64746e;      //0-3
					*((uint*)@new + 1) = 0x6c642e6c;//4-7
					*((ushort*)@new + 4) = 0x006c;  //8-9
					*(@new + 10) = 0;               //10
                    
					for (int i = 0; i < 11; i++)
						*(modName + i) = *(@new + i);

                    //write "NtContinue\0" to function name
                    VirtualProtect(funcName, 11, 0x40, out _);
                    *(uint*)@new = 0x6f43744e;
					*((uint*)@new + 1) = 0x6e69746e;
					*((ushort*)@new + 4) = 0x6575;
					*(@new + 10) = 0;

					for (int i = 0; i < 11; i++)
						*(funcName + i) = *(@new + i);
				}
                #endregion

                #region remove all section names
                for (int i = 0; i < sectNum; i++) {
                    //overwrite section name with zeroes
					VirtualProtect(ptr, 8, 0x40, out _);
					Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);

                    //jump to next section
					ptr += 0x28;
				}
                #endregion

                #region fuck CLR metadata
                //for stuff below, see: 
                //https://codingwithspike.wordpress.com/2012/08/12/building-a-net-disassembler-part-3-parsing-the-text-section/

                //unprotect 0x48 bytes of CLR metadata (#~ stream/table)
                VirtualProtect(mdDir, 0x48, 0x40, out _);

                //get ptr to MetaDataDirectoryAddress
                byte* mdHdr = modBase + *(uint*)(mdDir + 8);

                //overwrite some values
                *(uint*)mdDir = 0;      //header size
				*((uint*)mdDir + 1) = 0;//runtime version
				*((uint*)mdDir + 2) = 0;//MetaDataDirectoryAddress
				*((uint*)mdDir + 3) = 0;//MetaDataDirectorySize

                //overwrite the magic number 424a5342 (BSJB) in the md header
                VirtualProtect(mdHdr, 4, 0x40, out _);
				*(uint*)mdHdr = 0;

                //jump 12 bytes, to VersionStringLength
				mdHdr += 12;
				mdHdr += *(uint*)mdHdr;         //jump past version string
				mdHdr = (byte*)(((ulong)mdHdr + 7) & ~3UL); //something idk
				mdHdr += 2;
				ushort numOfStream = *mdHdr;    //read number of streams
				mdHdr += 2;

                //loop through streams and clear their names
				for (int i = 0; i < numOfStream; i++) {
                    //this would overwrite the offset and size
					VirtualProtect(mdHdr, 8, 0x40, out _);
					//*(uint*)mdHdr = 0;
					mdHdr += 4;
					//*(uint*)mdHdr = 0;
					mdHdr += 4;

                    //null-terminated, 4byte aligned string (ends with 1-4 nulls)
                    for (int ii = 0; ii < 8; ii++) {    //8x at most
                        //unprotect 4 bytes
						VirtualProtect(mdHdr, 4, 0x40, out _);

                        //first byte doesn't matter, always set to 0
						*mdHdr = 0; mdHdr++;

                        //check second byte
						if (*mdHdr == 0) {
							mdHdr += 3;
							break;
						}
						*mdHdr = 0; mdHdr++;

                        //third byte
						if (*mdHdr == 0) {
							mdHdr += 2;
							break;
						}
						*mdHdr = 0; mdHdr++;

                        //fourth byte
						if (*mdHdr == 0) {
							mdHdr += 1;
							break;
						}
						*mdHdr = 0; mdHdr++;
					}
				}
                #endregion
            }
			else //Flat
			{
				//VirtualProtect(ptr - 16, 8, 0x40, out old);
				//*(uint*)(ptr - 12) = 0;
				uint mdDir = *(uint*)(ptr - 0x10);      //CLRRuntimeHeader
				//*(uint*)(ptr - 16) = 0;
				uint importDir = *(uint*)(ptr - 0x78);  //offset of import table/directory

                #region remove all section names, get all addresses
                var vAdrs = new uint[sectNum];
				var vSizes = new uint[sectNum];
				var rAdrs = new uint[sectNum];
				for (int i = 0; i < sectNum; i++) {
                    //overwrite section name
					VirtualProtect(ptr, 8, 0x40, out _);
					Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);

                    //read 
					vAdrs[i] = *(uint*)(ptr + 12);  //VirtualAddress (RVA)
					vSizes[i] = *(uint*)(ptr + 8);  //VirtualSize
					rAdrs[i] = *(uint*)(ptr + 20);  //PointerToRawData

                    //skip to next
					ptr += 0x28;
				}
                #endregion

                #region overwrite some function to NtContinue in ntdll
                if (importDir != 0) {
                    //if any RVA section contains the import table, change our pointer to the corresponding rawdata section
                    //you'll see this code pattern more later
                    for (int i = 0; i < sectNum; i++)
                        //if vAdrs contains importDir
						if (vAdrs[i] <= importDir && importDir < vAdrs[i] + vSizes[i]) {
                            //move from RVA to raw table
                            //note: doesn't actually move the data, just our offset (importDir) to it
							importDir = importDir - vAdrs[i] + rAdrs[i];
							break;
						}

                    //get pointers
					byte* importDirPtr = modBase + importDir;   //ptr to real Import Table
					uint oftMod = *(uint*)importDirPtr;         //ptr to Import Lookup Table RVA

                    //fix import lookup table ptr...
                    for (int i = 0; i < sectNum; i++)
						if (vAdrs[i] <= oftMod && oftMod < vAdrs[i] + vSizes[i]) {
							oftMod = oftMod - vAdrs[i] + rAdrs[i];
							break;
						}

                    //get pointers, read module/DLL name
					byte* oftModPtr = modBase + oftMod;
					uint modName = *(uint*)(importDirPtr + 12);

                    //fix ptr...
					for (int i = 0; i < sectNum; i++)
						if (vAdrs[i] <= modName && modName < vAdrs[i] + vSizes[i]) {
							modName = modName - vAdrs[i] + rAdrs[i];
							break;
						}

                    //fix ptr...
					uint funcName = *(uint*)oftModPtr + 2;
					for (int i = 0; i < sectNum; i++)
						if (vAdrs[i] <= funcName && funcName < vAdrs[i] + vSizes[i]) {
							funcName = funcName - vAdrs[i] + rAdrs[i];
							break;
						}

                    //write "ntdll.dll\0\0" to modBase
					VirtualProtect(modBase + modName, 11, 0x40, out _);
					*(uint*)@new = 0x6c64746e;
					*((uint*)@new + 1) = 0x6c642e6c;
					*((ushort*)@new + 4) = 0x006c;
					*(@new + 10) = 0;
					for (int i = 0; i < 11; i++)
						*(modBase + modName + i) = *(@new + i);

                    //write "NtContinue\0" to funcName
                    VirtualProtect(modBase + funcName, 11, 0x40, out _);
					*(uint*)@new = 0x6f43744e;
					*((uint*)@new + 1) = 0x6e69746e;
					*((ushort*)@new + 4) = 0x6575;
					*(@new + 10) = 0;
					for (int i = 0; i < 11; i++)
						*(modBase + funcName + i) = *(@new + i);
				}
                #endregion

                //all below: fuck up CLR metadata. See the if-branch for docs, I'm too lazy to do the same work again.

                #region fuck CLR metadata
                //for docs, just see if-branch above. I'm not documenting this again.

                for (int i = 0; i < sectNum; i++)
					if (vAdrs[i] <= mdDir && mdDir < vAdrs[i] + vSizes[i]) {
						mdDir = mdDir - vAdrs[i] + rAdrs[i];
						break;
					}
				byte* mdDirPtr = modBase + mdDir;
				VirtualProtect(mdDirPtr, 0x48, 0x40, out _);
				uint mdHdr = *(uint*)(mdDirPtr + 8);
				for (int i = 0; i < sectNum; i++)
					if (vAdrs[i] <= mdHdr && mdHdr < vAdrs[i] + vSizes[i]) {
						mdHdr = mdHdr - vAdrs[i] + rAdrs[i];
						break;
					}
				*(uint*)mdDirPtr = 0;
				*((uint*)mdDirPtr + 1) = 0;
				*((uint*)mdDirPtr + 2) = 0;
				*((uint*)mdDirPtr + 3) = 0;


				byte* mdHdrPtr = modBase + mdHdr;
				VirtualProtect(mdHdrPtr, 4, 0x40, out _);
				*(uint*)mdHdrPtr = 0;
				mdHdrPtr += 12;
				mdHdrPtr += *(uint*)mdHdrPtr;
				mdHdrPtr = (byte*)(((ulong)mdHdrPtr + 7) & ~3UL);
				mdHdrPtr += 2;
				ushort numOfStream = *mdHdrPtr;
				mdHdrPtr += 2;
				for (int i = 0; i < numOfStream; i++) {
					VirtualProtect(mdHdrPtr, 8, 0x40, out _);
					//*(uint*)mdHdrPtr = 0;
					mdHdrPtr += 4;
					//*(uint*)mdHdrPtr = 0;
					mdHdrPtr += 4;
					for (int ii = 0; ii < 8; ii++) {
						VirtualProtect(mdHdrPtr, 4, 0x40, out _);
						*mdHdrPtr = 0;
						mdHdrPtr++;
						if (*mdHdrPtr == 0) {
							mdHdrPtr += 3;
							break;
						}
						*mdHdrPtr = 0;
						mdHdrPtr++;
						if (*mdHdrPtr == 0) {
							mdHdrPtr += 2;
							break;
						}
						*mdHdrPtr = 0;
						mdHdrPtr++;
						if (*mdHdrPtr == 0) {
							mdHdrPtr += 1;
							break;
						}
						*mdHdrPtr = 0;
						mdHdrPtr++;
					}
				}
                #endregion
            }
		}
	}
}