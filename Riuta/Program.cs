using System.Buffers.Binary;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using AsmResolver;
using AsmResolver.PE.File;

namespace Riuta
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Tauri Asset Extractor");
            Console.WriteLine("by Ulysses, wdwxy12345@gmail.com");
            Console.WriteLine();

            if (args.Length < 1)
            {
                Console.WriteLine("Usage: Riuta <path to Tauri executable>");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("File not found.");
                return;
            }

            Extract(args[0]);

            Console.WriteLine("Done.");
        }

        static void Extract(string path, string indexFile = "")
        {
            if (string.IsNullOrWhiteSpace(indexFile))
            {
                indexFile = "/index.html";
            }

            PEFile peFile = PEFile.FromFile(path);
            var imageBase = peFile.OptionalHeader.ImageBase;
            var rdata = peFile.Sections.First(s => s.Name == ".rdata");
            var rdataSpan = rdata.ToArray().AsSpan();
            var rdataStart = imageBase + rdata.Rva;
            var rdataEnd = rdataStart + rdata.GetPhysicalSize();

            ulong ToDataOffset(ulong address)
            {
                return address - imageBase - rdata.Rva;
            }

            bool InSection(ulong address)
            {
                return address >= rdataStart && address < rdataEnd;
            }

            ulong ToVirtualAddress(int offset)
            {
                return imageBase + rdata.Rva + (uint)offset;
            }

            // Find the index file in the .rdata section
            int index;
            int refIndex = -1;
            Span<byte> addressBytes = stackalloc byte[8];
            do
            {
                var l = rdataSpan.FindIndexOf(Encoding.UTF8.GetBytes(indexFile));
                if (l > int.MaxValue)
                {
                    break;
                }
                index = (int)l;
                
                if (index >= 3)
                {
                    //get previous 3 bytes
                    var offset = index - 3;
                    var sample = rdataSpan.Slice((int)offset, 3);
                    if (sample.SequenceEqual("to "u8))
                    {
                        // ` not found; fallback to index.html\0', not what we want
                        continue;
                    }

                    offset = index + 1;
                    if (offset >= rdataSpan.Length)
                    {
                        continue;
                    }

                    if (rdataSpan[offset] == 0)
                    {
                        continue; // there should be something
                    }

                    // check xref
                    var address = ToVirtualAddress(index);
                    
                    BinaryPrimitives.WriteUInt64LittleEndian(addressBytes, address);

                    int refIdx;
                    do
                    {
                        refIdx = (int)rdataSpan.FindIndexOf(addressBytes);

                        if (refIdx < 0)
                        {
                            break;
                        }

                        var fileNameLength = BinaryPrimitives.ReadInt64LittleEndian(rdataSpan.Slice(refIdx + 8, 8));
                        if (fileNameLength == indexFile.Length)
                        {
                            refIndex = refIdx;
                            break;
                        }
                    } while (refIdx > 0);

                    if (refIndex >= 0)
                    {
                        break;
                    }
                }
            } while (index >= 0);

            if (refIndex < 0)
            {
                Console.WriteLine("Failed: Cannot find pattern.");
                return;
            }
            
            //BrotliStream level 9
        }
    }
}
