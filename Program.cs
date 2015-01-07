using Mono.Options;
using System;
using System.Collections.Generic;
using System.Console;
using System.Linq;
using System.IO.File;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Blamite.IO;
using Blamite.Blam;
using Blamite.Blam.CacheFileLoader;
using System.Security.Cryptography;
using Blamite.Flexibility.Settings.XMLEngineDatabaseLoader;
using System.Globalization;

namespace BitmapInjectionHelper
{
	public class Program
	{
		public static void Main(string[] args)
		{
			WriteLine("Blam Bitmap Injection Helper");
			WriteLine("This only works on Halo 3. ha.");
			WriteLine("No exception handleing or anything like that. It might break.");
			WriteLine("If you don't like that, fuck off and do it by hand.");

			string blamCachePath = null;
			string imageRawPath = null;
			string mipMapsRawPath = null;
			int mipMapsCount = -1;
			int bitmapWidth = -1;
			int bitmapHeight = -1;
			string imageFormat = null;

			bool doinMipMaps = false;
			bool showHelp = false;

			var engineDb = LoadDatabase("Formats/Engines.xml");
			ICacheFile cacheFile;

			#region [ Validation and Setup ]

			WriteLine("Started Validation and Setup");

			var p = new OptionSet {
				"Usage: bitmapinjectionhelper <blam_cache_path> [options]",
				"<blam_cache_path> : The Path to the Blam Cache to inject into.",
				"options:",
					{ "ir|imageraw=", "The Path to the Image Raw to inject.", v => imageRawPath = v },
					{ "mr|mipsraw=", "The Path to the MipMaps Raw to inject (optional, required if you're injecting MipMaps).", v => mipMapsRawPath = v },
					{ "mc|mipscount=", "The MipMaps count.", v => mipMapsCount = int.Parse(v) },
					{ "bw|bitmapwidth=", "The Width of the bitmap you're injecting.", v => bitmapWidth = int.Parse(v) },
					{ "bh|bitmapheight=", "The Height of the bitmap you're injecting.", v => bitmapHeight = int.Parse(v) },
					{ "if|imageformat=", "THe hex string (ie; 0x0154) of the format of the image raw. You probally want to leave this alone. (optional)", v => imageFormat = v },
					{ "h|help",  "Show Help (this message) and exits", v => showHelp = v != null }
			};

			var extra = new List<string>();
			try
			{
				extra = p.Parse(args);
				blamCachePath = extra.First();
			}
			catch (Exception)
			{
				WriteLine("Try `bitmapinjectionhelper --help` for more information.");
#if DEBUG
				ReadLine();
#endif
				return;
			}

			if (showHelp)
			{
				p.WriteOptionDescriptions(Out);
#if DEBUG
				ReadLine();
#endif
				return;
			}

			#endregion


			#region [ Check if we doin' MipMaps ]

			WriteLine("Checking if we're doing MipMaps...");

			// Are we doin mipmaps?
			doinMipMaps = mipMapsRawPath != null && Exists(mipMapsRawPath);

			if (doinMipMaps)
				WriteLine("We doin MipMaps!");
			else
				WriteLine("We ain't doin MipMaps... :(");

			#endregion


			#region [ Expanding the Map ]

			WriteLine("Expand the Cache");

			var imageRawLength = new FileInfo(imageRawPath).Length;
			var mipMapsRawLength = doinMipMaps ? new FileInfo(mipMapsRawPath).Length : 0;
			var totalRawLength = imageRawLength + mipMapsRawLength;

			var pagesToExpand = totalRawLength / 0x1000;
			var mapexpandProcess = new Process
			{
				StartInfo = new ProcessStartInfo("mapexpand.exe")
				{
					Arguments = String.Format("\"{0}\" resource {1}", blamCachePath, pagesToExpand),
					UseShellExecute = false,
					RedirectStandardOutput = true,
					CreateNoWindow = true
				}
			};
			mapexpandProcess.Start();
			var expandedRawOffset = -1;
			while (!mapexpandProcess.StandardOutput.EndOfStream)
			{
				string line = mapexpandProcess.StandardOutput.ReadLine();
				WriteLine(line);

				if (line.Contains("Successfully injected"))
				{
					var matches = Regex.Matches(line, @"0x[0-9a-f]+", RegexOptions.IgnoreCase);
					var cleanHexString = matches[1].Value.Remove(0, 2);
					expandedRawOffset = Convert.ToInt32(cleanHexString, 16);
				}
			}

			#endregion


			#region [ Injecting Raw Data ]

			WriteLine("Injecting Raw Data...");

			if (doinMipMaps)
			{
				using (var fs = new FileStream(blamCachePath, FileMode.Open))
				{
					using (var writer = new EndianWriter(fs, Endian.BigEndian))
					{
						writer.SeekTo(expandedRawOffset);
						writer.WriteBlock(ReadAllBytes(mipMapsRawPath));
					}
				}
			}

			using (var fs = new FileStream(blamCachePath, FileMode.Open))
			{
				using (var writer = new EndianWriter(fs, Endian.BigEndian))
				{
					writer.SeekTo(expandedRawOffset + mipMapsRawLength);
					writer.WriteBlock(ReadAllBytes(imageRawPath));
				}
			}

			WriteLine("Done..");

			#endregion


			#region [ Play Fixin' ] 

			WriteLine("Started Fixing stuff in `play`");

			using (var stream = new EndianStream(Open(blamCachePath, FileMode.Open), Endian.BigEndian))
			{
				cacheFile = LoadCacheFile(stream, engineDb);
				var resourceTable = cacheFile.Resources.LoadResourceTable(stream);

				var segment = resourceTable.Resources.Last();
				if (segment.Location.PrimaryOffset != -1)
					segment.Location.PrimaryOffset = 0;
				if (segment.Location.SecondaryOffset != -1)
					segment.Location.SecondaryOffset = 0;

				if (doinMipMaps)
				{
					var mipMapsRawPage = resourceTable.Pages[resourceTable.Pages.Count() - 2];
					mipMapsRawPage.CompressionMethod = Blamite.Blam.Resources.ResourcePageCompression.None;
					mipMapsRawPage.FilePath = (cacheFile.ScenarioName == "mainmenu" ? "maps\\mainmenu.map" : null);
					mipMapsRawPage.Offset = expandedRawOffset - cacheFile.RawTable.Offset;
					mipMapsRawPage.UncompressedSize = (int)mipMapsRawLength;
					mipMapsRawPage.CompressedSize = (int)mipMapsRawLength;

					var mipsCrcHashData = Hashing.GetHashes(ReadAllBytes(mipMapsRawPath));
					mipMapsRawPage.Checksum = mipsCrcHashData.CRC;
					mipMapsRawPage.Hash1 = mipsCrcHashData.EntireBufferHash;
					mipMapsRawPage.Hash2 = mipsCrcHashData.FirstChunkHash;
					mipMapsRawPage.Hash3 = mipsCrcHashData.LastChunkHash;
				}

				var bitmapRawPage = resourceTable.Pages.Last();
				bitmapRawPage.CompressionMethod = Blamite.Blam.Resources.ResourcePageCompression.None;
				bitmapRawPage.FilePath = (cacheFile.ScenarioName == "mainmenu" ? "maps\\mainmenu.map" : null);
				bitmapRawPage.Offset = (int)((expandedRawOffset - cacheFile.RawTable.Offset) + mipMapsRawLength);
				bitmapRawPage.UncompressedSize = (int)imageRawLength;
				bitmapRawPage.CompressedSize = (int)imageRawLength;

				var bitmapCrcHashData = Hashing.GetHashes(ReadAllBytes(imageRawPath));
				bitmapRawPage.Checksum = bitmapCrcHashData.CRC;
				bitmapRawPage.Hash1 = bitmapCrcHashData.EntireBufferHash;
				bitmapRawPage.Hash2 = bitmapCrcHashData.FirstChunkHash;
				bitmapRawPage.Hash3 = bitmapCrcHashData.LastChunkHash;

				cacheFile.Resources.SaveResourceTable(resourceTable, stream);
			}

			WriteLine("Done...");

			#endregion


			#region [ Zone Fix Up ]

			WriteLine("Started Zone Fix Ups...");

			using (var stream = new EndianStream(Open(blamCachePath, FileMode.Open), Endian.BigEndian))
			{
				cacheFile = LoadCacheFile(stream, engineDb);
				var zone = cacheFile.Tags.FindTagByClass("zone");
				var resourceTable = cacheFile.Resources.LoadResourceTable(stream);

				var bitmapTagResource = resourceTable.Resources.Last();
				using (var ms = new MemoryStream(bitmapTagResource.Info))
				using (var endian = new EndianStream(ms, Endian.BigEndian))
				{
					endian.SeekTo(0x14);

					// image raw length
					var fixupSize = endian.ReadInt32();
					if (fixupSize != 0x00)
					{
						endian.SeekTo(0x14);
						endian.WriteInt32((int)imageRawLength);
					}

					// bitmap size
					endian.SeekTo(0x28);
					endian.WriteInt16((short)bitmapWidth);
					endian.WriteInt16((short)bitmapHeight);

					// mipmaps
					endian.SeekTo(0x2D);
					endian.WriteByte((byte)(mipMapsCount + 1));

					// format
					if (imageFormat != null)
					{
						var format = short.Parse(imageFormat.ToLowerInvariant().Replace("0x", ""), NumberStyles.HexNumber);
						endian.SeekTo(0x30);
						endian.WriteInt16(format);
					}
				}

				cacheFile.Resources.SaveResourceTable(resourceTable, stream);
			}

			WriteLine("Done...");

			#endregion


#if DEBUG
			ReadLine();
#endif
		}
	}

	public static class Hashing
	{
		#region Salt

		private static readonly byte[] Salt = new byte[34]
		{
			237,
			212,
			48,
			9,
			102,
			109,
			92,
			74,
			92,
			54,
			87,
			250,
			180,
			14,
			2,
			47,
			83,
			90,
			198,
			201,
			238,
			71,
			31,
			1,
			241,
			164,
			71,
			86,
			183,
			113,
			79,
			28,
			54,
			236
		};

		#endregion

		public static HashData GetHashes(byte[] bytes)
		{
			if (bytes.Length < 1024)
				throw new InvalidDataException(string.Format("The file size is too small! It must be at least one kilobyte."));
			return new HashData()
			{
				CRC = CountCrc(bytes),
				EntireBufferHash = GetEntireBufferHash(bytes),
				FirstChunkHash = GetFirstChunkHash(bytes),
				LastChunkHash = GetLastChunkHash(bytes)
			};
		}

		public static byte[] GetEntireBufferHash(byte[] bytes)
		{
			byte[] hash = new byte[0];
			using (SHA1 shA1 = SHA1.Create())
			{
				byte[] buffer = new byte[34 + bytes.Length];
				Array.Copy(Salt, buffer, 34);
				Array.Copy(bytes, 0, buffer, 34, bytes.Length);
				if (shA1 != null)
					hash = shA1.ComputeHash(buffer);
			}
			return hash;
		}

		public static byte[] GetFirstChunkHash(byte[] bytes)
		{
			if (bytes.Length < 1024)
				throw new Exception("byte array less than 400 bytes");
			byte[] hash = new byte[0];
			using (SHA1 shA1 = SHA1.Create())
			{
				byte[] buffer = new byte[1058];
				Array.Copy(Salt, buffer, 34);
				Array.Copy(bytes, 0, buffer, 34, 1024);
				if (shA1 != null)
					hash = shA1.ComputeHash(buffer);
			}
			return hash;
		}

		public static byte[] GetLastChunkHash(byte[] bytes)
		{
			if (bytes.Length < 1024)
				throw new InvalidDataException("byte array less than 400 bytes");
			byte[] hash = new byte[0];
			using (SHA1 shA1 = SHA1.Create())
			{
				byte[] buffer = new byte[1058];
				Array.Copy(Salt, buffer, 34);
				Array.Copy(bytes, bytes.Length - 1024, buffer, 34, 1024);
				if (shA1 != null)
					hash = shA1.ComputeHash(buffer);
			}
			return hash;
		}

		private static uint CountCrc(IList<byte> pBuf)
		{
			uint c = uint.MaxValue;
			uint[] numArray = new uint[256]
			{
				0U,
				1996959894U,
				3993919788U,
				2567524794U,
				124634137U,
				1886057615U,
				3915621685U,
				2657392035U,
				249268274U,
				2044508324U,
				3772115230U,
				2547177864U,
				162941995U,
				2125561021U,
				3887607047U,
				2428444049U,
				498536548U,
				1789927666U,
				4089016648U,
				2227061214U,
				450548861U,
				1843258603U,
				4107580753U,
				2211677639U,
				325883990U,
				1684777152U,
				4251122042U,
				2321926636U,
				335633487U,
				1661365465U,
				4195302755U,
				2366115317U,
				997073096U,
				1281953886U,
				3579855332U,
				2724688242U,
				1006888145U,
				1258607687U,
				3524101629U,
				2768942443U,
				901097722U,
				1119000684U,
				3686517206U,
				2898065728U,
				853044451U,
				1172266101U,
				3705015759U,
				2882616665U,
				651767980U,
				1373503546U,
				3369554304U,
				3218104598U,
				565507253U,
				1454621731U,
				3485111705U,
				3099436303U,
				671266974U,
				1594198024U,
				3322730930U,
				2970347812U,
				795835527U,
				1483230225U,
				3244367275U,
				3060149565U,
				1994146192U,
				31158534U,
				2563907772U,
				4023717930U,
				1907459465U,
				112637215U,
				2680153253U,
				3904427059U,
				2013776290U,
				251722036U,
				2517215374U,
				3775830040U,
				2137656763U,
				141376813U,
				2439277719U,
				3865271297U,
				1802195444U,
				476864866U,
				2238001368U,
				4066508878U,
				1812370925U,
				453092731U,
				2181625025U,
				4111451223U,
				1706088902U,
				314042704U,
				2344532202U,
				4240017532U,
				1658658271U,
				366619977U,
				2362670323U,
				4224994405U,
				1303535960U,
				984961486U,
				2747007092U,
				3569037538U,
				1256170817U,
				1037604311U,
				2765210733U,
				3554079995U,
				1131014506U,
				879679996U,
				2909243462U,
				3663771856U,
				1141124467U,
				855842277U,
				2852801631U,
				3708648649U,
				1342533948U,
				654459306U,
				3188396048U,
				3373015174U,
				1466479909U,
				544179635U,
				3110523913U,
				3462522015U,
				1591671054U,
				702138776U,
				2966460450U,
				3352799412U,
				1504918807U,
				783551873U,
				3082640443U,
				3233442989U,
				3988292384U,
				2596254646U,
				62317068U,
				1957810842U,
				3939845945U,
				2647816111U,
				81470997U,
				1943803523U,
				3814918930U,
				2489596804U,
				225274430U,
				2053790376U,
				3826175755U,
				2466906013U,
				167816743U,
				2097651377U,
				4027552580U,
				2265490386U,
				503444072U,
				1762050814U,
				4150417245U,
				2154129355U,
				426522225U,
				1852507879U,
				4275313526U,
				2312317920U,
				282753626U,
				1742555852U,
				4189708143U,
				2394877945U,
				397917763U,
				1622183637U,
				3604390888U,
				2714866558U,
				953729732U,
				1340076626U,
				3518719985U,
				2797360999U,
				1068828381U,
				1219638859U,
				3624741850U,
				2936675148U,
				906185462U,
				1090812512U,
				3747672003U,
				2825379669U,
				829329135U,
				1181335161U,
				3412177804U,
				3160834842U,
				628085408U,
				1382605366U,
				3423369109U,
				3138078467U,
				570562233U,
				1426400815U,
				3317316542U,
				2998733608U,
				733239954U,
				1555261956U,
				3268935591U,
				3050360625U,
				752459403U,
				1541320221U,
				2607071920U,
				3965973030U,
				1969922972U,
				40735498U,
				2617837225U,
				3943577151U,
				1913087877U,
				83908371U,
				2512341634U,
				3803740692U,
				2075208622U,
				213261112U,
				2463272603U,
				3855990285U,
				2094854071U,
				198958881U,
				2262029012U,
				4057260610U,
				1759359992U,
				534414190U,
				2176718541U,
				4139329115U,
				1873836001U,
				414664567U,
				2282248934U,
				4279200368U,
				1711684554U,
				285281116U,
				2405801727U,
				4167216745U,
				1634467795U,
				376229701U,
				2685067896U,
				3608007406U,
				1308918612U,
				956543938U,
				2808555105U,
				3495958263U,
				1231636301U,
				1047427035U,
				2932959818U,
				3654703836U,
				1088359270U,
				936918000U,
				2847714899U,
				3736837829U,
				1202900863U,
				817233897U,
				3183342108U,
				3401237130U,
				1404277552U,
				615818150U,
				3134207493U,
				3453421203U,
				1423857449U,
				601450431U,
				3009837614U,
				3294710456U,
				1567103746U,
				711928724U,
				3020668471U,
				3272380065U,
				1510334235U,
				755167117U
			};
			int count = pBuf.Count;
			for (int index = 0; index < count; ++index)
				c = numArray[((int)c ^ pBuf[index]) & byte.MaxValue] ^ c >> 8;
			return c;
		}
	}

	public class HashData
	{
		public byte[] EntireBufferHash { get; set; }

		public byte[] FirstChunkHash { get; set; }

		public byte[] LastChunkHash { get; set; }

		public uint CRC { get; set; }
	}
}
