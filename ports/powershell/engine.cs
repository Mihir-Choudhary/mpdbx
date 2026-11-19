// mpdbx engine for the PowerShell edition (C# 5, compiled by Add-Type). Same rules as mpdbx / mpdbx.py.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Mpdbx
{
    public static class Crypto
    {
        public static readonly byte[] Key = Hex(
            "1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54faa21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c" +
            "9cbce48e23d05371ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe3c8a775233557dde13a8b14087cc1bc8f10f6e" +
            "cdd083a959cff84a9d1d50755e3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd0291771861a54b4c285a9a3db7aca" +
            "6d224aeacd621db9f2a22ed1e9e11d75bed7dc0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429ba495676b8398db" +
            "2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253");
        public static readonly byte[] Magic = Encoding.ASCII.GetBytes("SQLite format 3\0");

        public static byte[] Hex(string h)
        {
            var b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }

        public static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        public static byte[] Keystream(int n)
        {
            var s = new int[256];
            for (int i = 0; i < 256; i++) s[i] = i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + Key[i % Key.Length]) & 0xFF;
                int t = s[i]; s[i] = s[j]; s[j] = t;
            }
            var o = new byte[n];
            int a = 0; j = 0;
            for (int k = 0; k < n; k++)
            {
                a = (a + 1) & 0xFF;
                j = (j + s[a]) & 0xFF;
                int t = s[a]; s[a] = s[j]; s[j] = t;
                o[k] = (byte)s[(s[a] + s[j]) & 0xFF];
            }
            return o;
        }
    }

    public class WalReport
    {
        public bool Present, HeaderValid, BigEndian;
        public uint PageSize, Salt1, Salt2;
        public int FramesTotal, FramesValid, FramesApplied, Commits, IgnoredTail;
        public string Stop;
    }

    public class Images
    {
        public byte[] DbOnly, Merged;
        public int PageSize, Pages;
        public bool Encrypted;
        public WalReport Wal = new WalReport();
        public List<string> Notes = new List<string>();
        public byte H18, H19;
    }

    public static class Pager
    {
        static uint Be32(byte[] b, int o) { return (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]); }

        class Codec
        {
            public bool Enc; public byte[] Ks;
            public byte[] Page(byte[] src, int off, int len, bool first)
            {
                var o = new byte[len];
                Buffer.BlockCopy(src, off, o, 0, len);
                if (!Enc) return o;
                if (first)
                {
                    Buffer.BlockCopy(Crypto.Magic, 0, o, 0, 16);
                    for (int i = 24; i < len; i++) o[i] ^= Ks[i - 24];
                }
                else for (int i = 0; i < len; i++) o[i] ^= Ks[i];
                return o;
            }
        }

        static void Ck(byte[] d, int off, int len, ref uint s0, ref uint s1, bool big)
        {
            int n = len / 8;
            for (int i = 0; i < n; i++)
            {
                int o = off + i * 8;
                uint a = big ? Be32(d, o) : BitConverter.ToUInt32(d, o);
                uint b = big ? Be32(d, o + 4) : BitConverter.ToUInt32(d, o + 4);
                unchecked { s0 = s0 + a + s1; s1 = s1 + b + s0; }
            }
        }

        public static Images Build(byte[] db, byte[] wal)
        {
            if (db.Length < 100) throw new Exception("database file is empty or truncated");
            var im = new Images();
            im.Encrypted = !db.Take(16).SequenceEqual(Crypto.Magic);
            if (im.Encrypted)
            {
                var ks = Crypto.Keystream(16);
                for (int i = 0; i < 16; i++) if ((db[i] ^ ks[i]) != Crypto.Magic[i])
                        throw new Exception("page 1 does not decrypt to the SQLite magic: not an mpenginedb.db, or a newer key");
            }
            int v = db[16] << 8 | db[17];
            int ps = v == 1 ? 65536 : v;
            if (ps < 512 || ps > 65536 || (ps & (ps - 1)) != 0) throw new Exception("bad page size " + ps);
            im.PageSize = ps;
            im.Pages = db.Length / ps;
            if (im.Pages == 0) throw new Exception("database file is empty or truncated");
            if (!im.Encrypted) im.Notes.Add("input is a plain (unencrypted) SQLite file");
            if (db.Length % ps != 0) im.Notes.Add("trailing partial page of " + (db.Length % ps) + " bytes ignored");
            var c = new Codec { Enc = im.Encrypted, Ks = im.Encrypted ? Crypto.Keystream(ps) : null };
            im.DbOnly = new byte[im.Pages * ps];
            for (int p = 0; p < im.Pages; p++) Buffer.BlockCopy(c.Page(db, p * ps, ps, p == 0), 0, im.DbOnly, p * ps, ps);
            im.H18 = im.DbOnly[18]; im.H19 = im.DbOnly[19];
            im.Wal.Present = wal != null;
            im.Merged = wal == null ? im.DbOnly : Replay(im, wal, c);
            return im;
        }

        static byte[] Replay(Images im, byte[] w, Codec codec)
        {
            var r = im.Wal; int ps = im.PageSize; var dbo = im.DbOnly;
            if (w.Length < 32) { im.Notes.Add("WAL has " + w.Length + " bytes (< 32-byte header); not applied"); return dbo; }
            uint magic = Be32(w, 0);
            bool big = (magic & 1) == 1;
            r.BigEndian = big; r.PageSize = Be32(w, 8); r.Salt1 = Be32(w, 16); r.Salt2 = Be32(w, 20);
            uint h0 = 0, h1 = 0; Ck(w, 0, 24, ref h0, ref h1, big);
            r.HeaderValid = (magic & ~1u) == 0x377f0682 && Be32(w, 4) == 3007000 && h0 == Be32(w, 24) && h1 == Be32(w, 28);
            if (!r.HeaderValid) { im.Notes.Add("WAL header invalid (magic, version or checksum); not applied"); return dbo; }
            if (r.PageSize != ps) { im.Notes.Add("WAL page size " + r.PageSize + " differs from DB page size " + ps + "; not applied"); r.HeaderValid = false; return dbo; }
            int fsz = 24 + ps;
            r.FramesTotal = (w.Length - 32) / fsz;
            uint c0 = h0, c1 = h1; int last = -1; uint lastPages = 0; int txn = 0; long orig = dbo.Length / ps; long maxPg = 0;
            int off = 32, idx = 0;
            while (off + fsz <= w.Length)
            {
                uint pg = Be32(w, off), commit = Be32(w, off + 4);
                if (Be32(w, off + 8) != r.Salt1 || Be32(w, off + 12) != r.Salt2) { r.Stop = "salt mismatch at frame " + idx + " (offset " + off + ")"; break; }
                uint a = c0, b = c1;
                Ck(w, off, 8, ref a, ref b, big);
                Ck(w, off + 24, ps, ref a, ref b, big);
                if (a != Be32(w, off + 16) || b != Be32(w, off + 20)) { r.Stop = "checksum mismatch at frame " + idx + " (offset " + off + ")"; break; }
                if (pg == 0) { r.Stop = "page number 0 at frame " + idx; break; }
                c0 = a; c1 = b;
                maxPg = Math.Max(maxPg, pg);
                if (commit != 0)
                {
                    if (commit > Math.Max(orig, maxPg) || (long)commit * ps > 2L * 1024 * 1024 * 1024) { r.Stop = "bad commit size " + commit + " at frame " + idx; break; }
                    int bad = -1;
                    for (int i = txn; i <= idx; i++) if (Be32(w, 32 + i * fsz) > commit) { bad = i; break; }
                    if (bad >= 0) { r.Stop = "page " + Be32(w, 32 + bad * fsz) + " beyond commit size at frame " + bad; break; }
                    last = idx; lastPages = commit; r.Commits++; txn = idx + 1;
                }
                r.FramesValid++; idx++; off += fsz;
            }
            if (r.Stop == null && off < w.Length) r.Stop = "truncated frame at offset " + off;
            if (last < 0) { r.IgnoredTail = r.FramesValid; return dbo; }
            r.FramesApplied = last + 1; r.IgnoredTail = r.FramesValid - r.FramesApplied;
            var m = new byte[(long)lastPages * ps];
            Buffer.BlockCopy(dbo, 0, m, 0, (int)Math.Min(dbo.Length, m.Length));
            for (int i = 0; i <= last; i++)
            {
                int o = 32 + i * fsz;
                uint pg = Be32(w, o);
                if (pg > lastPages) continue;
                Buffer.BlockCopy(codec.Page(w, o + 24, ps, pg == 1), 0, m, (int)(pg - 1) * ps, ps);
            }
            return m;
        }
    }

    /// Small helpers the WinForms GUI needs at speed.
    public static class Ui
    {
        /// Stable order of row indices by one column (case-insensitive, leading "▲ " ignored).
        public static int[] Order(List<string[]> rows, int col, bool desc)
        {
            var idx = Enumerable.Range(0, rows.Count).ToArray();
            Func<int, string> key = i => { var s = col < rows[i].Length ? (rows[i][col] ?? "") : ""; return s.StartsWith("▲ ") ? s.Substring(2) : s; };
            var o = desc ? idx.OrderByDescending(key, StringComparer.OrdinalIgnoreCase) : idx.OrderBy(key, StringComparer.OrdinalIgnoreCase);
            return o.ToArray();
        }

        /// Order of events by time; untimed events stay last in both directions.
        public static int[] OrderByTime(List<Event> es, bool desc)
        {
            var idx = Enumerable.Range(0, es.Count);
            var timed = idx.Where(i => es[i].Time.HasValue);
            var t = desc ? timed.OrderByDescending(i => es[i].Time.Value) : timed.OrderBy(i => es[i].Time.Value);
            return t.Concat(idx.Where(i => !es[i].Time.HasValue)).ToArray();
        }

        /// Rows whose cells contain the needle (case-insensitive); all rows when the needle is empty.
        public static List<int> Filter(List<string[]> rows, string needle)
        {
            var o = new List<int>();
            string n = (needle ?? "").Trim();
            for (int i = 0; i < rows.Count; i++)
                if (n == "" || rows[i].Any(c => c != null && c.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)) o.Add(i);
            return o;
        }

        /// Histogram of event times into n buckets (counts, min, max).
        public static long[] Histogram(List<Event> es, int n, out long lo, out long hi)
        {
            var ts = es.Where(e => e.Time.HasValue).Select(e => e.Time.Value).ToList();
            var c = new long[Math.Max(n, 1)];
            lo = ts.Count > 0 ? ts.Min() : 0; hi = ts.Count > 0 ? ts.Max() : 0;
            long span = Math.Max(hi - lo, 1);
            foreach (var t in ts) c[Math.Min(n - 1, (int)((t - lo) * (decimal)n / (span + 1)))]++;
            return c;
        }
    }

    // ------------------------------------------------------------------ SQLite (Windows' own winsqlite3.dll)
    public static class Sql
    {
        const string L = "winsqlite3.dll";
        [DllImport(L)] static extern int sqlite3_open_v2(byte[] name, out IntPtr db, int flags, IntPtr vfs);
        [DllImport(L)] static extern int sqlite3_deserialize(IntPtr db, byte[] schema, IntPtr data, long sz, long buf, uint flags);
        [DllImport(L)] static extern IntPtr sqlite3_malloc64(ulong n);
        [DllImport(L)] static extern void sqlite3_free(IntPtr p);
        [DllImport(L)] static extern int sqlite3_close_v2(IntPtr db);
        [DllImport(L)] static extern int sqlite3_prepare16_v2(IntPtr db, [MarshalAs(UnmanagedType.LPWStr)] string sql, int n, out IntPtr st, IntPtr tail);
        [DllImport(L)] static extern int sqlite3_step(IntPtr st);
        [DllImport(L)] static extern int sqlite3_finalize(IntPtr st);
        [DllImport(L)] static extern int sqlite3_column_count(IntPtr st);
        [DllImport(L)] static extern IntPtr sqlite3_column_name16(IntPtr st, int i);
        [DllImport(L)] static extern int sqlite3_column_type(IntPtr st, int i);
        [DllImport(L)] static extern long sqlite3_column_int64(IntPtr st, int i);
        [DllImport(L)] static extern double sqlite3_column_double(IntPtr st, int i);
        [DllImport(L)] static extern IntPtr sqlite3_column_text(IntPtr st, int i);
        [DllImport(L)] static extern IntPtr sqlite3_column_blob(IntPtr st, int i);
        [DllImport(L)] static extern int sqlite3_column_bytes(IntPtr st, int i);
        [DllImport(L)] static extern IntPtr sqlite3_errmsg16(IntPtr db);

        static readonly List<string> TempFiles = new List<string>();
        static byte[] Z(string s) { return Encoding.UTF8.GetBytes(s + "\0"); }

        /// UTF-8 text with every invalid byte kept as \xNN (mpdbx sqldb::text_lossless).
        public static string TextLossless(byte[] b)
        {
            var sb = new StringBuilder(b.Length);
            int i = 0;
            while (i < b.Length)
            {
                int n = Utf8SeqLen(b, i);
                if (n > 0) { sb.Append(Encoding.UTF8.GetString(b, i, n)); i += n; }
                else
                {
                    int bad = Math.Max(1, -n);
                    for (int k = 0; k < bad && i < b.Length; k++, i++) sb.Append("\\x").Append(b[i].ToString("x2"));
                }
            }
            return sb.ToString();
        }

        /// Length of the valid UTF-8 sequence at i (>0), or -(number of bytes to treat as invalid), following Rust's
        /// Utf8Error::error_len (the maximal prefix of a valid sequence counts as one error).
        static int Utf8SeqLen(byte[] b, int i)
        {
            byte c = b[i];
            if (c < 0x80) return 1;
            int need; int lo = 0x80, hi = 0xBF;
            if (c >= 0xC2 && c <= 0xDF) need = 1;
            else if (c == 0xE0) { need = 2; lo = 0xA0; }
            else if (c >= 0xE1 && c <= 0xEC || c == 0xEE || c == 0xEF) need = 2;
            else if (c == 0xED) { need = 2; hi = 0x9F; }
            else if (c == 0xF0) { need = 3; lo = 0x90; }
            else if (c >= 0xF1 && c <= 0xF3) need = 3;
            else if (c == 0xF4) { need = 3; hi = 0x8F; }
            else return -1;
            for (int k = 1; k <= need; k++)
            {
                if (i + k >= b.Length) return -k;
                byte x = b[i + k];
                int l = k == 1 ? lo : 0x80, h = k == 1 ? hi : 0xBF;
                if (x < l || x > h) return -k;
            }
            return need + 1;
        }

        /// Read-only connection on a decrypted image (header 18-19 set to rollback-journal mode). `temp` receives the
        /// temporary file used when winsqlite3 lacks sqlite3_deserialize (caller deletes it after Close).
        public static IntPtr Open(byte[] img, out string temp)
        {
            temp = null;
            var b = (byte[])img.Clone();
            b[18] = 1; b[19] = 1;
            b[28] = 0; b[29] = 0; b[30] = 0; b[31] = 0; // in-header page count: SQLite sizes the database from the buffer
            IntPtr db = IntPtr.Zero, mem = IntPtr.Zero;
            try
            {
                if (sqlite3_open_v2(Z(":memory:"), out db, 0x02 | 0x04, IntPtr.Zero) != 0) throw new Exception("sqlite3_open_v2 failed");
                mem = sqlite3_malloc64((ulong)b.Length);
                if (mem == IntPtr.Zero) throw new OutOfMemoryException();
                Marshal.Copy(b, 0, mem, b.Length);
                // SQLITE_DESERIALIZE_FREEONCLOSE (1) | SQLITE_DESERIALIZE_READONLY (4): SQLite owns mem from here on
                int rc = sqlite3_deserialize(db, Z("main"), mem, b.Length, b.Length, 1 | 4);
                mem = IntPtr.Zero;
                if (rc != 0) throw new Exception("sqlite3_deserialize failed (" + rc + ")");
                return db;
            }
            catch (EntryPointNotFoundException)
            {
                if (mem != IntPtr.Zero) sqlite3_free(mem);
                if (db != IntPtr.Zero) sqlite3_close_v2(db);
                string p = Path.Combine(Path.GetTempPath(), "mpdbx_" + Guid.NewGuid().ToString("N") + ".db");
                File.WriteAllBytes(p, b);
                lock (TempFiles) TempFiles.Add(p);
                temp = p;
                if (sqlite3_open_v2(Z(p), out db, 0x01, IntPtr.Zero) != 0) { sqlite3_close_v2(db); throw new Exception("sqlite3_open_v2 failed on the temporary copy"); }
                return db;
            }
            catch
            {
                if (mem != IntPtr.Zero) sqlite3_free(mem);
                if (db != IntPtr.Zero) sqlite3_close_v2(db);
                throw;
            }
        }

        public static void Close(IntPtr db, string temp)
        {
            if (db != IntPtr.Zero) sqlite3_close_v2(db);
            if (temp != null) { try { File.Delete(temp); lock (TempFiles) TempFiles.Remove(temp); } catch { } }
        }

        /// Deletes any temporary copy still present (normally none: each is removed right after its tables are read).
        public static void Cleanup()
        {
            lock (TempFiles) { foreach (var p in TempFiles.ToArray()) { try { File.Delete(p); TempFiles.Remove(p); } catch { } } }
        }

        public static List<object[]> Query(IntPtr db, string sql, out string[] cols)
        {
            IntPtr st;
            if (sqlite3_prepare16_v2(db, sql, -1, out st, IntPtr.Zero) != 0)
            {
                cols = new string[0];
                throw new Exception(Marshal.PtrToStringUni(sqlite3_errmsg16(db)));
            }
            try
            {
                int n = sqlite3_column_count(st);
                cols = new string[n];
                for (int i = 0; i < n; i++) cols[i] = Marshal.PtrToStringUni(sqlite3_column_name16(st, i));
                var rows = new List<object[]>();
                while (true)
                {
                    int rc = sqlite3_step(st);
                    if (rc == 101) break;
                    if (rc != 100) throw new Exception(Marshal.PtrToStringUni(sqlite3_errmsg16(db)));
                    var r = new object[n];
                    for (int i = 0; i < n; i++)
                    {
                        switch (sqlite3_column_type(st, i))
                        {
                            case 1: r[i] = sqlite3_column_int64(st, i); break;
                            case 2: r[i] = sqlite3_column_double(st, i); break;
                            case 3:
                                IntPtr t = sqlite3_column_text(st, i);
                                int tl = sqlite3_column_bytes(st, i);
                                var tb = new byte[tl];
                                if (tl > 0) Marshal.Copy(t, tb, 0, tl);
                                r[i] = TextLossless(tb); break;
                            case 4:
                                int len = sqlite3_column_bytes(st, i);
                                var bb = new byte[len];
                                if (len > 0) Marshal.Copy(sqlite3_column_blob(st, i), bb, 0, len);
                                r[i] = bb; break;
                            default: r[i] = null; break;
                        }
                    }
                    rows.Add(r);
                }
                return rows;
            }
            finally { sqlite3_finalize(st); }
        }
    }

    /// Row identity: rowid, primary key, or the whole row (mpdbx RowKey).
    public class RowKey
    {
        public int Tag; public long Rowid; public object[] V;
        public static RowKey Of(long r) { return new RowKey { Tag = 0, Rowid = r }; }
        public override bool Equals(object o)
        {
            var k = o as RowKey;
            if (k == null || k.Tag != Tag) return false;
            return Tag == 0 ? k.Rowid == Rowid : Prov.RowEq(V, k.V);
        }
        public override int GetHashCode()
        {
            if (Tag == 0) return Rowid.GetHashCode();
            int h = Tag;
            foreach (var x in V) h = h * 31 + (x == null ? 0 : x is byte[] ? ((byte[])x).Length : x.GetHashCode());
            return h;
        }
        public byte[] Bytes()
        {
            var ms = new MemoryStream();
            ms.WriteByte((byte)Tag);
            if (Tag == 0) ms.Write(BitConverter.GetBytes(Rowid), 0, 8);
            else foreach (var v in V) Prov.Enc(v, ms);
            return ms.ToArray();
        }
        public string Label()
        {
            if (Tag == 0) return "rowid " + Rowid;
            return (Tag == 1 ? "pk (" : "row (") + string.Join(", ", V.Select(Fmt.Raw)) + ")";
        }
        public override string ToString() { return Label(); }
    }

    public class TableData
    {
        public string[] Columns = new string[0];
        public List<KeyValuePair<RowKey, object[]>> Rows = new List<KeyValuePair<RowKey, object[]>>();
        public string Error;
    }

    public class ProvRow { public RowKey Key; public object[] Values; public string Status; public object[] Old; }

    public class TableProv { public string[] Columns; public List<ProvRow> Rows = new List<ProvRow>(); public string Error; public int? DbOnly, Merged; }

    public static class Prov
    {
        static string Q(string n) { return "\"" + n.Replace("\"", "\"\"") + "\""; }

        /// All tables of one decrypted image (mpdbx sqldb: table_xinfo columns, rowid / primary key / whole-row keys).
        /// Throws when SQLite cannot read the schema at all.
        public static Dictionary<string, TableData> ReadImage(byte[] img)
        {
            string temp;
            IntPtr db = Sql.Open(img, out temp);
            try
            {
                string[] c;
                Sql.Query(db, "SELECT count(*) FROM sqlite_master", out c);
                var names = Sql.Query(db, "SELECT name, coalesce(sql,'') FROM sqlite_master WHERE type='table' ORDER BY name", out c);
                var o = new Dictionary<string, TableData>(StringComparer.Ordinal);
                foreach (var r in names)
                {
                    string n = (string)r[0];
                    if (n.StartsWith("sqlite_") && n != "sqlite_sequence" && n != "sqlite_stat1") continue;
                    o[n] = ReadTable(db, n, (string)r[1] ?? "");
                }
                return o;
            }
            finally { Sql.Close(db, temp); }
        }

        static TableData ReadTable(IntPtr db, string name, string sql)
        {
            var td = new TableData();
            string up = sql.ToUpperInvariant();
            int lp = up.LastIndexOf(')');
            var words = Regex.Split(lp >= 0 ? up.Substring(lp + 1) : up, @"[\s,]+").Where(w => w != "").ToList();
            bool withoutRowid = false;
            for (int i = 0; i + 1 < words.Count; i++) if (words[i] == "WITHOUT" && words[i + 1] == "ROWID") withoutRowid = true;
            List<object[]> info;
            try { string[] ic; info = Sql.Query(db, "PRAGMA table_xinfo(" + Q(name) + ")", out ic); }
            catch (Exception e) { td.Error = e.Message; return td; }
            if (info.Count == 0) { td.Error = "no column metadata"; return td; }
            var cols = info.Where(x => !(x[6] is long && (long)x[6] == 1)).Select(x => new { N = (string)x[1], Pk = x[5] is long ? (long)x[5] : 0 }).ToList();
            var pk = cols.Select((x, i) => new { x.Pk, I = i }).Where(x => x.Pk > 0).OrderBy(x => x.Pk).ThenBy(x => x.I).Select(x => x.I).ToList();
            string alias = withoutRowid ? null : new[] { "rowid", "_rowid_", "oid" }.FirstOrDefault(a => !cols.Any(x => x.N.Equals(a, StringComparison.OrdinalIgnoreCase)));
            td.Columns = cols.Select(x => x.N).ToArray();
            string sel = string.Join(", ", td.Columns.Select(Q));
            try
            {
                string[] cc;
                var rows = Sql.Query(db, alias != null ? "SELECT " + alias + ", " + sel + " FROM " + Q(name) : "SELECT " + sel + " FROM " + Q(name), out cc);
                foreach (var r in rows)
                {
                    if (alias != null)
                    {
                        var v = new object[r.Length - 1]; Array.Copy(r, 1, v, 0, v.Length);
                        td.Rows.Add(new KeyValuePair<RowKey, object[]>(RowKey.Of((long)r[0]), v));
                    }
                    else
                    {
                        var k = pk.Count > 0 ? new RowKey { Tag = 1, V = pk.Select(i => r[i]).ToArray() } : new RowKey { Tag = 2, V = (object[])r.Clone() };
                        td.Rows.Add(new KeyValuePair<RowKey, object[]>(k, r));
                    }
                }
            }
            catch (Exception e) { td.Rows.Clear(); td.Error = e.Message; }
            return td;
        }

        public static void Enc(object v, Stream o)
        {
            if (v == null) { o.WriteByte(0); return; }
            if (v is long) { o.WriteByte(1); o.Write(BitConverter.GetBytes((long)v), 0, 8); return; }
            if (v is double) { o.WriteByte(2); o.Write(BitConverter.GetBytes(BitConverter.DoubleToInt64Bits((double)v)), 0, 8); return; }
            byte[] d; byte tag;
            if (v is string) { d = Encoding.UTF8.GetBytes((string)v); tag = 3; } else { d = (byte[])v; tag = 4; }
            o.WriteByte(tag); o.Write(BitConverter.GetBytes((ulong)d.Length), 0, 8); o.Write(d, 0, d.Length);
        }

        public static bool ValEq(object a, object b)
        {
            if (a == null || b == null) return a == null && b == null;
            var ba = a as byte[]; var bb = b as byte[];
            if (ba != null || bb != null) return ba != null && bb != null && ba.SequenceEqual(bb);
            if (a is long && b is long) return (long)a == (long)b;
            if (a is double && b is double) return BitConverter.DoubleToInt64Bits((double)a) == BitConverter.DoubleToInt64Bits((double)b);
            if (a is string && b is string) return string.Equals((string)a, (string)b, StringComparison.Ordinal);
            return false;
        }

        public static bool RowEq(object[] a, object[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (!ValEq(a[i], b[i])) return false;
            return true;
        }

        class BytesCmp : IComparer<byte[]>
        {
            public int Compare(byte[] a, byte[] b)
            {
                int n = Math.Min(a.Length, b.Length);
                for (int i = 0; i < n; i++) if (a[i] != b[i]) return a[i].CompareTo(b[i]);
                return a.Length.CompareTo(b.Length);
            }
        }

        static TableProv ClassifyTable(TableData ta, TableData tb)
        {
            var tp = new TableProv { Columns = tb.Columns.Length > 0 || ta == null ? tb.Columns : ta.Columns };
            Action<IEnumerable<KeyValuePair<RowKey, object[]>>, string> addAll = (rows, s) => { foreach (var r in rows) tp.Rows.Add(new ProvRow { Key = r.Key, Values = r.Value, Status = s, Old = s == "Removed by WAL" ? r.Value : null }); };
            if (tb.Error != null)
            {
                tp.Error = tb.Error;
                if (ta != null && ta.Error == null) { tp.DbOnly = ta.Rows.Count; addAll(ta.Rows, "unknown"); }
            }
            else if (ta != null && ta.Error != null) { tp.Error = ta.Error; tp.Merged = tb.Rows.Count; addAll(tb.Rows, "unknown"); }
            else if (ta == null) { tp.DbOnly = 0; tp.Merged = tb.Rows.Count; addAll(tb.Rows, "WAL-only"); }
            else
            {
                tp.DbOnly = ta.Rows.Count; tp.Merged = tb.Rows.Count;
                var old = new Dictionary<RowKey, object[]>();
                foreach (var r in ta.Rows) old[r.Key] = r.Value;
                foreach (var r in tb.Rows)
                {
                    object[] ov;
                    if (old.TryGetValue(r.Key, out ov))
                    {
                        old.Remove(r.Key);
                        bool same = RowEq(ov, r.Value);
                        tp.Rows.Add(new ProvRow { Key = r.Key, Values = r.Value, Status = same ? "DB" : "WAL-modified", Old = same ? null : ov });
                    }
                    else tp.Rows.Add(new ProvRow { Key = r.Key, Values = r.Value, Status = "WAL-only" });
                }
                foreach (var k in old.Keys.OrderBy(k => k.Bytes(), new BytesCmp()))
                    tp.Rows.Add(new ProvRow { Key = k, Values = old[k], Status = "Removed by WAL", Old = old[k] });
            }
            return tp;
        }

        public static Dictionary<string, TableProv> Classify(Dictionary<string, TableData> a, Dictionary<string, TableData> b)
        {
            var o = new Dictionary<string, TableProv>(StringComparer.Ordinal);
            foreach (var kv in b) { TableData ta; a.TryGetValue(kv.Key, out ta); o[kv.Key] = ClassifyTable(ta, kv.Value); }
            foreach (var kv in a)
                if (!o.ContainsKey(kv.Key))
                {
                    var tp = ClassifyTable(kv.Value, new TableData());
                    tp.Columns = kv.Value.Columns;
                    o[kv.Key] = tp;
                }
            return o;
        }

        /// DB-only image unreadable: every merged row gets unknown provenance.
        public static Dictionary<string, TableProv> ClassifyUnknown(Dictionary<string, TableData> b, string err)
        {
            var o = new Dictionary<string, TableProv>(StringComparer.Ordinal);
            foreach (var kv in b)
            {
                var tp = new TableProv { Columns = kv.Value.Columns, Error = kv.Value.Error ?? err, Merged = kv.Value.Error == null ? (int?)kv.Value.Rows.Count : null };
                foreach (var r in kv.Value.Rows) tp.Rows.Add(new ProvRow { Key = r.Key, Values = r.Value, Status = "unknown" });
                o[kv.Key] = tp;
            }
            return o;
        }
    }

    // ------------------------------------------------------------------ formatting
    public static class Fmt
    {
        public const long PMin = 116444736000000000L, PMax = 150000000000000000L, RMax = 2650467743999999999L;

        public static long? Plausible(long? v) { return v.HasValue && v.Value >= PMin && v.Value < PMax ? v : null; }

        public static string Ft(long t, int tz)
        {
            long local = t + (long)tz * 600000000L;
            if (local < 0 || local > RMax) return t + " (raw)";
            long days = local / 864000000000L, rem = local % 864000000000L;
            var d = new DateTime(1601, 1, 1).AddDays(days);
            long secs = rem / 10000000L, frac = rem % 10000000L;
            return d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " " + (secs / 3600).ToString("00") + ":" + (secs / 60 % 60).ToString("00") + ":" +
                   (secs % 60).ToString("00") + "." + frac.ToString("0000000") + TzSuffix(tz);
        }

        public static string TzSuffix(int tz)
        {
            if (tz == 0) return "Z";
            int a = Math.Abs(tz);
            return (tz < 0 ? "-" : "+") + (a / 60).ToString("00") + ":" + (a % 60).ToString("00");
        }

        /// 'Z', 'UTC', '+HH:MM', '-HH:MM' (|offset| <= 14:00) -> minutes; null when invalid.
        public static int? ParseTz(string s)
        {
            s = (s ?? "").Trim();
            if (s.Any(ch => ch > 127)) return null;
            if (s.Equals("z", StringComparison.OrdinalIgnoreCase) || s.Equals("utc", StringComparison.OrdinalIgnoreCase)) return 0;
            var m = Regex.Match(s, "^([+-])([0-9]{2}):([0-9]{2})$");
            if (!m.Success) return null;
            int h = int.Parse(m.Groups[2].Value), mi = int.Parse(m.Groups[3].Value);
            if (mi >= 60 || h * 60 + mi > 840) return null;
            return (m.Groups[1].Value == "+" ? 1 : -1) * (h * 60 + mi);
        }

        public static string Classified(long v, int tz)
        {
            if (v == 0) return "0 (zero)";
            if (v == -1 || v == long.MaxValue) return v + " (max)";
            if (v < 0 || v > RMax) return v + " (opaque)";
            if (v >= PMin && v < PMax) return Ft(v, tz);
            return Ft(v, tz) + " (implausible)";
        }

        /// ISO 8601 subset YYYY-MM-DD[(T| )HH:MM[:SS[.f{1,7}]]][Z|±HH:MM] -> FILETIME (UTC); null when invalid (time.rs).
        public static long? ParseTime(string s, int tz)
        {
            s = (s ?? "").Trim();
            if (s.Length < 10 || s.Any(ch => ch > 127)) return null;
            var dm = Regex.Match(s.Substring(0, 10), "^([0-9]+)-([0-9]+)-([0-9]+)$");
            if (!dm.Success) return null;
            int y, mo, dd;
            if (!int.TryParse(dm.Groups[1].Value, out y) || !int.TryParse(dm.Groups[2].Value, out mo) || !int.TryParse(dm.Groups[3].Value, out dd)) return null;
            if (y < 1601 || y > 9999 || mo < 1 || mo > 12 || dd < 1 || dd > DateTime.DaysInMonth(y, mo)) return null;
            string rest = s.Substring(10);
            int zone = tz;
            if (rest.EndsWith("Z") || rest.EndsWith("z")) { zone = 0; rest = rest.Substring(0, rest.Length - 1); }
            else if (rest.Length >= 6 && (rest[rest.Length - 6] == '+' || rest[rest.Length - 6] == '-') && rest[rest.Length - 3] == ':')
            {
                var z = ParseTz(rest.Substring(rest.Length - 6));
                if (!z.HasValue) return null;
                zone = z.Value; rest = rest.Substring(0, rest.Length - 6);
            }
            long ticks = 0;
            if (rest.Length > 0)
            {
                if (rest[0] != 'T' && rest[0] != ' ') return null;
                string t = rest.Substring(1);
                int dot = t.IndexOf('.');
                string hms = dot < 0 ? t : t.Substring(0, dot);
                var parts = hms.Split(':');
                if (parts.Length < 2 || parts.Length > 3 || parts.Any(p => p.Length != 2 || !p.All(ch => ch >= '0' && ch <= '9'))) return null;
                int h = int.Parse(parts[0]), mi = int.Parse(parts[1]), se = parts.Length == 3 ? int.Parse(parts[2]) : 0;
                if (h > 23 || mi > 59 || se > 59) return null;
                if (dot >= 0)
                {
                    string f = t.Substring(dot + 1);
                    if (parts.Length != 3 || f.Length == 0 || f.Length > 7 || !f.All(ch => ch >= '0' && ch <= '9')) return null;
                    ticks += long.Parse(f) * (long)Math.Pow(10, 7 - f.Length);
                }
                ticks += (h * 3600L + mi * 60 + se) * 10000000L;
            }
            long days = (long)(new DateTime(y, mo, dd) - new DateTime(1601, 1, 1)).TotalDays;
            decimal utc = (decimal)days * 864000000000m + ticks - zone * 600000000m;
            return utc < 0 || utc > RMax ? (long?)null : (long)utc;
        }

        /// Rust f64 Display: shortest round-trip digits, never an exponent, no trailing ".0".
        public static string Float(double f)
        {
            if (double.IsNaN(f)) return "NaN";
            if (double.IsInfinity(f)) return f > 0 ? "inf" : "-inf";
            string r = f.ToString("R", CultureInfo.InvariantCulture);
            if (r.IndexOfAny(new[] { 'E', 'e' }) >= 0)
            {
                int e = r.IndexOfAny(new[] { 'E', 'e' });
                string mant = r.Substring(0, e); int exp = int.Parse(r.Substring(e + 1), CultureInfo.InvariantCulture);
                bool neg = mant.StartsWith("-"); if (neg) mant = mant.Substring(1);
                int dp = mant.IndexOf('.'); string digits = mant.Replace(".", ""); int point = (dp < 0 ? mant.Length : dp) + exp;
                if (point <= 0) r = "0." + new string('0', -point) + digits;
                else if (point >= digits.Length) r = digits + new string('0', point - digits.Length);
                else r = digits.Substring(0, point) + "." + digits.Substring(point);
                if (neg) r = "-" + r;
            }
            if (r.EndsWith(".0")) r = r.Substring(0, r.Length - 2);
            return r;
        }

        public static string Raw(object v)
        {
            if (v == null) return "";
            var b = v as byte[]; if (b != null) return Crypto.ToHex(b);
            if (v is double) return Float((double)v);
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        public static string Leaf(string p) { if (string.IsNullOrEmpty(p)) return ""; int i = p.LastIndexOfAny(new[] { '\\', '/' }); return i < 0 ? p : p.Substring(i + 1); }

        /// Per-scalar upper case; characters whose upper case expands stay as they are (path.rs upper).
        public static string Upper(string s)
        {
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                string sc = char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? s.Substring(i++, 2) : s[i].ToString();
                if (sc == "ı") { sb.Append('I'); continue; }      // dotless i (Unicode upper is I; .NET invariant keeps it)
                if (sc == "ſ") { sb.Append('S'); continue; }      // long s
                string u = sc.ToUpperInvariant();
                sb.Append(u.Length == sc.Length ? u : sc);
            }
            return sb.ToString();
        }

        static string Hex64(long v) { return ((ulong)v).ToString("X"); }

        public static string RegTypeName(long t)
        {
            string[] n = { "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ",
                           "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD" };
            return t >= 0 && t < n.Length ? n[t] : "0x" + Hex64(t) + " (unknown)";
        }

        static List<string> Utf16z(byte[] b)
        {
            var segs = new List<string>(); var cur = new List<byte>();
            for (int i = 0; i + 1 < b.Length; i += 2)
            {
                if (b[i] == 0 && b[i + 1] == 0) { segs.Add(Utf16Lossy(cur.ToArray())); cur.Clear(); }
                else { cur.Add(b[i]); cur.Add(b[i + 1]); }
            }
            segs.Add(Utf16Lossy(cur.ToArray()));
            return segs;
        }

        static string Utf16Lossy(byte[] b)
        {
            var sb = new StringBuilder();
            for (int i = 0; i + 1 < b.Length; i += 2)
            {
                char c = (char)(b[i] | b[i + 1] << 8);
                if (char.IsHighSurrogate(c) && i + 3 < b.Length && char.IsLowSurrogate((char)(b[i + 2] | b[i + 3] << 8))) { sb.Append(c).Append((char)(b[i + 2] | b[i + 3] << 8)); i += 2; }
                else if (char.IsSurrogate(c)) sb.Append('�');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        /// Registry data by type; malformed lengths fall back to hex (values.rs reg_data).
        public static string RegData(long t, byte[] b)
        {
            int n = b.Length;
            if (t == 4 && n == 4) return BitConverter.ToUInt32(b, 0).ToString();
            if (t == 5 && n == 4) return ((uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3])).ToString();
            if (t == 11 && n == 8) return BitConverter.ToUInt64(b, 0).ToString();
            if ((t == 1 || t == 2) && n % 2 == 0) return Utf16z(b)[0];
            if (t == 7 && n % 2 == 0) return string.Join(" | ", Utf16z(b).Where(x => x != ""));
            return Crypto.ToHex(b);
        }

        public static string EnumName(string field, long v)
        {
            if (field == "SCANREASON" && v == 2) return "on-open";
            if (field == "SCANREASON" && v == 5) return "on-close after write";
            return "0x" + Hex64(v) + " (unknown)";
        }

        public static string FlagBits(long sv)
        {
            ulong v = (ulong)sv;
            if (v == 0) return "0x0";
            var bits = Enumerable.Range(0, 64).Where(i => (v >> i & 1) == 1).Select(i => i.ToString());
            return "0x" + v.ToString("X") + " = bits " + string.Join(",", bits);
        }

        public static string Guid(byte[] b)
        {
            if (b.Length != 16) return null;
            return "{" + BitConverter.ToUInt32(b, 0).ToString("X8") + "-" + BitConverter.ToUInt16(b, 4).ToString("X4") + "-" + BitConverter.ToUInt16(b, 6).ToString("X4") + "-" +
                   b[8].ToString("X2") + b[9].ToString("X2") + "-" + string.Concat(b.Skip(10).Select(x => x.ToString("X2"))) + "}";
        }

        static readonly string[] GuidCols = { "guid", "ruleid", "hipsinjectionid", "folderguardid", "lsassreadmemid" };

        /// (display, raw) for any table cell by column name (load.rs decode_cell).
        public static string[] Cell(string name, object v, int tz)
        {
            string raw = Raw(v);
            bool timeish = name.EndsWith("Time") || name.EndsWith("TS") || name.Contains("TimeStamp");
            if (v is long)
            {
                long i = (long)v;
                if (timeish) return new[] { Classified(i, tz), raw };
                if (new[] { "ProcessIntegrity", "ProcessTaintReason", "Action", "RuleAction", "State" }.Contains(name)) return new[] { EnumName(name, i), raw };
                if (name.Contains("Flags")) return new[] { FlagBits(i), raw };
            }
            var b = v as byte[];
            if (b != null && b.Length == 16 && (GuidCols.Contains(name.ToLowerInvariant()) || name.EndsWith("Guid"))) return new[] { Guid(b), raw };
            return new[] { raw, raw };
        }

        /// Rust str::parse::<uN>: optional '+', ASCII digits, in range.
        public static ulong? UInt(string s, int bits)
        {
            if (s == null || !Regex.IsMatch(s, @"^\+?[0-9]{1,40}$")) return null;
            decimal v;
            if (!decimal.TryParse(s.TrimStart('+'), NumberStyles.None, CultureInfo.InvariantCulture, out v)) return null;
            decimal max = bits == 64 ? 18446744073709551615m : (decimal)((1UL << bits) - 1);
            return v <= max ? (ulong?)(ulong)v : null;
        }
    }

    // ------------------------------------------------------------------ paths
    public class WinPath { public string Kind; public object Arg; public List<string> Comps; public string Tag; }

    public static class Paths
    {
        static readonly Regex TagRx = new Regex("^ENG:([A-Z0-9_]+):(.*)$", RegexOptions.Singleline);

        public static string SplitTag(string s, out string body)
        {
            var m = TagRx.Match(s);
            if (m.Success) { body = m.Groups[2].Value; return "ENG:" + m.Groups[1].Value; }
            body = s; return null;
        }

        static List<string> Comps(string rest)
        {
            string r = rest.StartsWith("\\") ? rest.Substring(1) : rest;
            if (r == "") return new List<string>();
            var v = r.Split('\\').ToList();
            if (v.Count > 0 && v[v.Count - 1] == "") v.RemoveAt(v.Count - 1);
            return v;
        }

        static bool Drive(string x, out char d, out string rest)
        {
            d = '\0'; rest = null;
            if (x.Length >= 2 && x[0] < 128 && char.IsLetter(x[0]) && x[1] == ':' && (x.Length == 2 || x[2] == '\\')) { d = char.ToUpperInvariant(x[0]); rest = x.Substring(2); return true; }
            return false;
        }

        static bool Pre(string s, string p) { return s.Length >= p.Length && string.Compare(s, 0, p, 0, p.Length, StringComparison.OrdinalIgnoreCase) == 0; }

        public static WinPath Parse(string s)
        {
            string body; string tag = SplitTag(s, out body);
            string n = body.Replace('/', '\\');
            char d; string rest;
            foreach (var vp in new[] { "\\\\?\\", "\\??\\", "\\\\.\\" })
                if (Pre(n, vp))
                {
                    string r = n.Substring(vp.Length);
                    if (Pre(r, "UNC\\")) return new WinPath { Kind = "unc", Comps = Comps(r.Substring(4)), Tag = tag };
                    if (Drive(r, out d, out rest)) return new WinPath { Kind = "drive", Arg = d, Comps = Comps(rest), Tag = tag };
                    if (Pre(r, "Volume{")) return new WinPath { Kind = "vguid", Comps = Comps(r), Tag = tag };
                    return new WinPath { Kind = "other", Comps = new List<string> { n }, Tag = tag };
                }
            const string dev = "\\Device\\HarddiskVolume";
            if (Pre(n, dev))
            {
                string r = n.Substring(dev.Length);
                int k = 0; while (k < r.Length && r[k] >= '0' && r[k] <= '9') k++;
                string tail = r.Substring(k);
                uint num;
                if (k > 0 && k <= 10 && uint.TryParse(r.Substring(0, k), NumberStyles.None, CultureInfo.InvariantCulture, out num) && (tail == "" || tail.StartsWith("\\")))
                    return new WinPath { Kind = "device", Arg = num, Comps = Comps(tail), Tag = tag };
            }
            if (Pre(n, "\\SystemRoot") && (n.Length == 11 || n[11] == '\\')) return new WinPath { Kind = "sysroot", Comps = Comps(n.Substring(11)), Tag = tag };
            if (Drive(n, out d, out rest)) return new WinPath { Kind = "drive", Arg = d, Comps = Comps(rest), Tag = tag };
            if (n.StartsWith("\\\\")) return new WinPath { Kind = "unc", Comps = Comps(n.Substring(2)), Tag = tag };
            return new WinPath { Kind = "other", Comps = new List<string> { n }, Tag = tag };
        }

        static string J(string pre, IEnumerable<string> cs) { var sb = new StringBuilder(pre); foreach (var c in cs) { sb.Append('\\'); sb.Append(Fmt.Upper(c)); } return sb.ToString(); }

        public static string Key(WinPath p, Dictionary<uint, char> vm, char? sysroot)
        {
            switch (p.Kind)
            {
                case "drive": return J((char)p.Arg + ":", p.Comps);
                case "device":
                    char d; return vm.TryGetValue((uint)p.Arg, out d) ? J(d + ":", p.Comps) : J("\\DEVICE\\HARDDISKVOLUME" + p.Arg, p.Comps);
                case "sysroot": return sysroot.HasValue ? J(sysroot.Value + ":", new[] { "WINDOWS" }.Concat(p.Comps)) : J("\\SYSTEMROOT", p.Comps);
                case "unc": return "\\" + J("", p.Comps);
                case "vguid": return J("\\\\?", p.Comps);
                default: return Fmt.Upper(string.Join("\\", p.Comps));
            }
        }

        public static string Class(WinPath p, Dictionary<uint, char> vm)
        {
            if (p.Kind == "sysroot") return "system dir";
            if (p.Kind == "device" && !vm.ContainsKey((uint)p.Arg)) return "unknown";
            if (p.Kind == "drive" || p.Kind == "device")
            {
                string c = p.Comps.Count > 0 ? Fmt.Upper(p.Comps[0]) : null;
                return c == "WINDOWS" || c == "PROGRAM FILES" || c == "PROGRAM FILES (X86)" ? "system dir" : "outside system dirs";
            }
            return "unknown";
        }
    }

    // ------------------------------------------------------------------ export guard
    public static class Guard
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);
        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION { public uint Attr; public long C, A, W; public uint Vsn, SizeHi, SizeLo, Links, IdxHi, IdxLo; }

        static string Id(string p)
        {
            try
            {
                using (var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    BY_HANDLE_FILE_INFORMATION i;
                    return GetFileInformationByHandle(fs.SafeFileHandle, out i) ? i.Vsn + ":" + i.IdxHi + ":" + i.IdxLo : null;
                }
            }
            catch { return null; }
        }

        /// Throws when the destination is an input file: same full path, or the same file under another name (hard link, junction).
        /// ':' outside a leading drive designator names an NTFS alternate data stream (created inside another file).
        public static bool HasStream(string p)
        {
            string s = p;
            foreach (var pre in new[] { "\\\\?\\", "\\\\.\\" }) if (s.StartsWith(pre)) s = s.Substring(pre.Length);
            if (s.Length >= 2 && s[0] < 128 && char.IsLetter(s[0]) && s[1] == ':') s = s.Substring(2);
            return s.Contains(":");
        }

        public static void Check(string path, IEnumerable<string> inputs)
        {
            if (HasStream(path)) throw new Exception(path + " names an NTFS alternate data stream; choose a plain file name");
            string full = Path.GetFullPath(path);
            string did = File.Exists(full) ? Id(full) : null;
            foreach (var i in inputs)
            {
                if (string.Equals(Path.GetFullPath(i), full, StringComparison.OrdinalIgnoreCase)) throw new Exception("refusing to overwrite an input file: " + path);
                if (did != null && did == Id(i)) throw new Exception("refusing to overwrite an input file (same file under another name): " + path);
            }
        }

        /// One harmless file-name component (no separators, no leading dots, no reserved device names).
        public static string SafeName(string s)
        {
            string n = Regex.Replace(s, @"[^\w&() .-]+", "_").Trim(' ', '.');
            if (n == "") n = "_";
            string stem = n.Split('.')[0].ToUpperInvariant();
            if (new[] { "CON", "PRN", "AUX", "NUL" }.Contains(stem) || Regex.IsMatch(stem, "^(COM|LPT)[0-9]$")) n = "_" + n;
            return n.Length > 150 ? n.Substring(0, 150) : n;
        }
    }

    // ------------------------------------------------------------------ events
    public class Field { public string Name, Display, Raw; public Field(string n, string d, string r) { Name = n; Display = d; Raw = r; } }

    public class Event
    {
        public int Id; public string Kind; public long? Time; public string Summary; public int Loc = -1; public List<Field> Fields;
        public string Table; public RowKey Key; public string Status; public object[] Old; public bool Flag; public string Text;
        public string F(string name) { foreach (var f in Fields) if (f.Name == name) return f.Display; return null; }
    }

    public class Location { public int Id; public string Key; public List<string> Spellings = new List<string>(); public string Cls; public List<int> Events = new List<int>(); }

    public class HostFact { public string Label, Value, Table, Status; }

    public class Card { public string Level, Title, Explain; public HashSet<int> Ids; public List<string> Examples; }

    public class Facets
    {
        public HashSet<string> Kinds, Status, Cls; public bool Flagged; public HashSet<int> Only; public string Special;
        public Facets Clone() { return (Facets)MemberwiseClone(); }
    }

    public class Case
    {
        public static readonly Dictionary<string, string> KindLabel = new Dictionary<string, string> {
            {"ProcessFirstStart","Process first start"},{"ModuleFirstLoad","Module first load"},{"NoCertExec","No-cert execution"},
            {"OfnSet","OriginalFileName set"},{"OfnSetInferred","OriginalFileName (inferred)"},{"OfnProcessed","OFN processed"},
            {"FileContext","Defender file context"},{"LowFiHit","LowFi signature hit"},{"FileHashed","File hashed"},
            {"StoreExpiry","Store cache expiry"},{"RegistryChange","Registry change"},{"QueueEntry","Queue entry"},{"RdpLogon","RDP logon"},
            {"BmRecord","Behaviour-monitor record"}};
        public static readonly HashSet<string> Routine = new HashSet<string> { "ModuleFirstLoad", "FileHashed", "StoreExpiry", "OfnProcessed", "FileContext" };
        public static readonly string[] WalStatuses = { "WAL-only", "WAL-modified", "Removed by WAL" };
        static readonly string[] BmExtra = { "RansomwareDetections", "ProcessBlockHistory", "SystemFileCache" };
        static readonly Dictionary<string, string> DigestFields = new Dictionary<string, string> { { "md5", "MD5 (column SHA1)" }, { "sha1", "SHA1 (column MD5)" }, { "sha256", "SHA256 (column SHA256)" } };
        const long BpiLag = 7 * 864000000000L;
        const long MaxInput = 2L * 1024 * 1024 * 1024;

        public int Tz; public string Path;
        public List<string[]> Inputs = new List<string[]>(); // path, bytes, sha256, modified
        public Images Img;
        public Dictionary<string, TableProv> Tables;
        public List<Event> Events = new List<Event>();
        public List<Location> Locations = new List<Location>();
        public List<HostFact> Host = new List<HostFact>();
        public List<string> Warnings = new List<string>();
        public Dictionary<uint, char> VolMap = new Dictionary<uint, char>();
        public char? SysRoot;
        Dictionary<string, int> locIndex = new Dictionary<string, int>(StringComparer.Ordinal);

        public Case(string path, int tz)
        {
            Tz = tz; Path = path;
            string db = Directory.Exists(path) ? System.IO.Path.Combine(path, "mpenginedb.db") : path;
            if (!File.Exists(db)) throw new Exception("no mpenginedb.db at " + path);
            byte[] raw = ReadShared(db);
            Inputs.Add(new[] { db, raw.Length.ToString(), Sha(raw), Mtime(db) });
            byte[] wal = null;
            if (File.Exists(db + "-wal"))
            {
                try { wal = ReadShared(db + "-wal"); Inputs.Add(new[] { db + "-wal", wal.Length.ToString(), Sha(wal), Mtime(db + "-wal") }); }
                catch (Exception e) { Warnings.Add("WAL unreadable (" + e.Message + "); loaded the database alone"); }
            }
            Img = Pager.Build(raw, wal);
            Warnings.AddRange(Img.Notes);
            Dictionary<string, TableData> tb;
            try { tb = Prov.ReadImage(Img.Merged); }
            catch (Exception e) { throw new Exception("merged image unreadable: " + e.Message); }
            try
            {
                var ta = object.ReferenceEquals(Img.Merged, Img.DbOnly) ? tb : Prov.ReadImage(Img.DbOnly);
                Tables = Prov.Classify(ta, tb);
            }
            catch (Exception e)
            {
                Warnings.Add("DB-only image unreadable (" + e.Message + "); provenance unknown");
                Tables = Prov.ClassifyUnknown(tb, e.Message);
            }
            Load();
            foreach (var e in Events)
            {
                var sb = new StringBuilder();
                sb.Append(e.Summary).Append(' ').Append(PathOf(e)).Append(' ').Append(e.Loc >= 0 ? Locations[e.Loc].Key : "").Append(' ').Append(KindLabel[e.Kind]);
                foreach (var f in e.Fields) sb.Append(' ').Append(f.Display).Append(' ').Append(f.Raw);
                e.Text = sb.ToString().ToLowerInvariant();
            }
        }

        static byte[] ReadShared(string p)
        {
            using (var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (fs.Length > MaxInput) throw new Exception(p + " is larger than 2 GiB");
                var ms = new MemoryStream();
                var buf = new byte[1 << 20];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    if (ms.Length + n > MaxInput) throw new Exception(p + " is larger than 2 GiB");
                    ms.Write(buf, 0, n);
                }
                return ms.ToArray();
            }
        }

        static string Sha(byte[] b) { using (var s = SHA256.Create()) return Crypto.ToHex(s.ComputeHash(b)); }
        static string Mtime(string p) { try { return Fmt.Ft(File.GetLastWriteTimeUtc(p).ToFileTimeUtc(), 0); } catch { return ""; } }

        Dictionary<string, int> Cols(string t)
        {
            var d = new Dictionary<string, int>();
            var cs = Tables[t].Columns ?? new string[0];
            for (int i = 0; i < cs.Length; i++) d[cs[i].ToLowerInvariant()] = i;
            return d;
        }

        static string Text(object v) { if (v is string) return (string)v; if (v is long) return ((long)v).ToString(CultureInfo.InvariantCulture); return null; }
        static long? Int(object v)
        {
            if (v is long) return (long)v;
            var s = v as string;
            if (s != null && Regex.IsMatch(s.Trim(), "^[+-]?[0-9]{1,19}$")) { long x; if (long.TryParse(s.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out x)) return x; }
            return null;
        }

        class R
        {
            public RowKey Key; public object[] V; public string Status; public object[] Old; public Dictionary<string, int> Idx;
            public object G(string c) { int i; return c != null && Idx.TryGetValue(c.ToLowerInvariant(), out i) && i < V.Length ? V[i] : null; }
        }

        IEnumerable<R> All(string t)
        {
            var idx = Cols(t);
            foreach (var r in Tables[t].Rows) yield return new R { Key = r.Key, V = r.Values, Status = r.Status, Old = r.Old, Idx = idx };
        }

        IEnumerable<R> Rows(string t, string[] req, string what)
        {
            var idx = Cols(t);
            var miss = req.Where(c => !idx.ContainsKey(c.ToLowerInvariant())).ToList();
            if (miss.Count > 0) { Warnings.Add("table " + t + " lacks column(s) " + string.Join(", ", miss) + "; " + what + " events skipped"); return new R[0]; }
            return All(t);
        }

        void Load()
        {
            var paths = new List<WinPath>();
            var pc = new[] { new[]{"BackupProcessInfo","FilePath"}, new[]{"AttributePersistContext","FilePath"}, new[]{"FileLowFiAsync","FileName"},
                new[]{"BmProcessInfo","ImageFileName"}, new[]{"BmFileInfo","DosPath"}, new[]{"BmFileInfo","NormalizedPath"}, new[]{"BmFileStartupActions","FilePath"},
                new[]{"ProcessBlockHistory","ProcessPath"}, new[]{"ProcessBlockHistory","TargetPath"}, new[]{"SystemFileCache","SystemFilePath"} };
            foreach (var x in pc)
            {
                if (!Tables.ContainsKey(x[0])) continue;
                int i; if (!Cols(x[0]).TryGetValue(x[1].ToLowerInvariant(), out i)) continue;
                foreach (var r in Tables[x[0]].Rows) { var s = i < r.Values.Length ? Text(r.Values[i]) : null; if (s != null) paths.Add(Paths.Parse(s)); }
            }
            if (Tables.ContainsKey("RollingQueuesValues"))
            {
                var qi = Cols("RollingQueuesValues"); int ti, ki;
                if (qi.TryGetValue("entrytable", out ti) && qi.TryGetValue("entrykey", out ki))
                    foreach (var r in Tables["RollingQueuesValues"].Rows)
                    {
                        string tq = ti < r.Values.Length ? Text(r.Values[ti]) : null;
                        string k = ki < r.Values.Length ? Text(r.Values[ki]) : null;
                        if ((tq == "RQ_RecentExecDropped" || tq == "RQ_RecentScriptDropped") && k != null) paths.Add(Paths.Parse(k));
                    }
            }
            InferVolMap(paths);
            foreach (var name in Tables.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                var tp = Tables[name];
                if (tp.Error != null) Warnings.Add("table " + name + ": " + tp.Error);
                switch (name)
                {
                    case "BackupProcessInfo": Bpi(name); break;
                    case "AttributePersistContext": Apc(name); break;
                    case "FileHashes": Hashes(name); break;
                    case "FileLowFiAsync": LowFi(name); break;
                    case "AmsiFileCache": Amsi(name); break;
                    case "SystemRegistryCache": Reg(name); break;
                    case "RollingQueuesValues": Queues(name); break;
                    case "FolderGuardPaths": Cfa(name); break;
                    case "SQLiteGlobals": case "DynSigRevisions": case "Engine": case "InventoryState": HostRows(name); break;
                    default: if (name.StartsWith("Bm") || BmExtra.Contains(name)) Bm(name); break;
                }
            }
        }

        void InferVolMap(List<WinPath> paths)
        {
            var dev = new Dictionary<uint, HashSet<string>>(); var drv = new Dictionary<char, HashSet<string>>();
            foreach (var p in paths)
            {
                if (p.Comps.Count == 0) continue;
                string rel = string.Join("\\", p.Comps.Select(Fmt.Upper));
                if (p.Kind == "device") { HashSet<string> s; if (!dev.TryGetValue((uint)p.Arg, out s)) dev[(uint)p.Arg] = s = new HashSet<string>(); s.Add(rel); }
                else if (p.Kind == "drive") { HashSet<string> s; if (!drv.TryGetValue((char)p.Arg, out s)) drv[(char)p.Arg] = s = new HashSet<string>(); s.Add(rel); }
            }
            foreach (var kv in dev)
            {
                var hits = drv.Select(x => new { D = x.Key, N = x.Value.Count(kv.Value.Contains) }).Where(x => x.N > 0).ToList();
                if (hits.Count == 1 && hits[0].N >= 2) VolMap[kv.Key] = hits[0].D;
            }
            var win = drv.Where(x => x.Value.Any(p => p == "WINDOWS" || p.StartsWith("WINDOWS\\"))).Select(x => x.Key).ToList();
            if (win.Count == 1) SysRoot = win[0];
        }

        public int Location(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return -1;
            var p = Paths.Parse(raw);
            string key = Paths.Key(p, VolMap, SysRoot);
            int id;
            if (locIndex.TryGetValue(key, out id)) { var l = Locations[id]; if (!l.Spellings.Contains(raw)) l.Spellings.Add(raw); return id; }
            var loc = new Location { Id = Locations.Count, Key = key, Cls = Paths.Class(p, VolMap) };
            loc.Spellings.Add(raw);
            Locations.Add(loc); locIndex[key] = loc.Id;
            return loc.Id;
        }

        public string Cls(int loc) { return loc >= 0 ? Locations[loc].Cls : "unknown"; }
        public string PathOf(Event e) { return e.Loc >= 0 ? Locations[e.Loc].Spellings[0] : ""; }
        public string KeyLabel(RowKey k) { return k.Label(); }
        public string TimeStr(long? t) { return t.HasValue ? Fmt.Ft(t.Value, Tz) : "—"; }

        Event Push(string kind, long? time, string summary, int loc, List<Field> fields, string table, R r, bool flag)
        {
            var e = new Event { Id = Events.Count, Kind = kind, Time = time, Summary = summary, Loc = loc, Fields = fields, Table = table, Key = r.Key, Status = r.Status, Old = r.Old,
                Flag = flag || r.Status == "WAL-only" || r.Status == "Removed by WAL" };
            Events.Add(e);
            if (loc >= 0) Locations[loc].Events.Add(e.Id);
            return e;
        }

        Field Tf(string name, object v) { var iv = Int(v); return new Field(name, iv.HasValue ? Fmt.Classified(iv.Value, Tz) : "", iv.HasValue ? iv.Value.ToString() : ""); }

        void Bpi(string t)
        {
            foreach (var r in Rows(t, new[] { "FilePath", "FirstStartTime", "InstanceTimeStamp" }, "process/module first-start"))
            {
                string path = Text(r.G("FilePath")) ?? "";
                long? fst = Int(r.G("FirstStartTime")), its = Int(r.G("InstanceTimeStamp"));
                int loc = Location(path);
                long? pf = Fmt.Plausible(fst), pi = Fmt.Plausible(its);
                long? start = (pf.HasValue && pi.HasValue && pi.Value >= pf.Value && pi.Value - pf.Value <= BpiLag) || (pf.HasValue && !pi.HasValue) ? pf : null;
                string raw = fst.HasValue ? fst.Value.ToString() : "";
                Field ff = start.HasValue ? Tf("FirstStartTime", fst) : pf.HasValue ? new Field("FirstStartTime", raw + " (module value; date-like by chance, not a start time)", raw) : new Field("FirstStartTime", raw + " (opaque)", raw);
                var fields = new List<Field> { new Field("Path", path, path), ff, Tf("InstanceTimeStamp", its) };
                var u = Int(r.G("NextUSN")); if (u.HasValue) fields.Add(new Field("NextUSN", u.ToString(), u.ToString()));
                if (start.HasValue) Push("ProcessFirstStart", start, "Process first start: " + Fmt.Leaf(path), loc, fields, t, r, false);
                else Push("ModuleFirstLoad", pi, "Module first load: " + Fmt.Leaf(path), loc, fields, t, r, false);
            }
        }

        static readonly Regex OfnRx = new Regex(@"^[\w.\- ]+\.(exe|dll|sys|com|scr|ocx|cpl|mui|efi|drv)$", RegexOptions.IgnoreCase | RegexOptions.ECMAScript);

        public static string RenameKind(string fname, string ofn)
        {
            string f = fname.ToLowerInvariant(), o = ofn.ToLowerInvariant();
            int dot = f.LastIndexOf('.'); string ext = dot < 0 ? f : f.Substring(dot + 1);
            if (Regex.IsMatch(f, @"\.(mui|efi|tlb)(_[0-9a-f]{8})?$") || Regex.IsMatch(f, "_[0-9a-f]{8}$") || Regex.IsMatch(ext, "^[0-9a-f]{40}$") || o.EndsWith(".mui") || Regex.IsMatch(f, @"^[0-9a-f]+_[0-9]+\.[0-9]+"))
                return "resource/component";
            if (Regex.IsMatch(f, @"\.(exe|dll|sys|scr|com|cpl|ocx)$")) return "executable rename";
            return "other";
        }

        void Apc(string t)
        {
            foreach (var r in Rows(t, new[] { "FilePath", "Context", "InsertTime" }, "attribute-context"))
            {
                string rawPath = Text(r.G("FilePath")) ?? "", ctx = Text(r.G("Context")) ?? "";
                string body; string tag = Paths.SplitTag(rawPath, out body);
                string path = tag != null ? rawPath.Substring(tag.Length + 1) : rawPath;
                long? ins = Int(r.G("InsertTime"));
                int loc = Location(path);
                bool outside = Cls(loc) == "outside system dirs";
                var fields = new List<Field> { new Field("Path", path, rawPath), new Field("Context", ctx, ctx), Tf("InsertTime", ins), Tf("ExpireTime", r.G("ExpireTime")) };
                if (tag != null) fields.Add(new Field("Engine tag", tag, tag));
                string name = Fmt.Leaf(path), kind, summ; bool flag;
                if (tag == null && ctx == "ExecutedPENoCert") { kind = "NoCertExec"; summ = "Execution, no embedded cert: " + name; flag = outside; }
                else if (tag == "ENG:OFNSET" || (tag == null && OfnRx.IsMatch(ctx) && !ctx.Equals(Fmt.Leaf(path), StringComparison.OrdinalIgnoreCase)))
                {
                    bool inferred = tag == null;
                    string rk = ctx.Equals(name, StringComparison.OrdinalIgnoreCase) ? "same as file name" : RenameKind(name, ctx);
                    fields.Add(new Field("OriginalFileName", ctx, ctx)); fields.Add(new Field("Rename kind", rk, rk));
                    kind = inferred ? "OfnSetInferred" : "OfnSet";
                    summ = "OriginalFileName " + ctx + " on " + name + (inferred ? " (inferred)" : "");
                    flag = rk == "executable rename" && outside;
                }
                else if (tag == "ENG:OFNPROCESSED") { kind = "OfnProcessed"; summ = "OFN processed: " + name; flag = false; }
                else { kind = "FileContext"; summ = "Defender file context " + ctx + ": " + name; flag = false; }
                Push(kind, Fmt.Plausible(ins), summ, loc, fields, t, r, flag);
            }
        }

        void Hashes(string t)
        {
            foreach (var r in Rows(t, new[] { "VSN", "FileID", "InstanceTimeStamp" }, "file-hash"))
            {
                object fid = r.G("FileID"), vsn = r.G("VSN");
                string fref = null, vs = null;
                if (fid is long && vsn is long)
                {
                    ulong v = (ulong)(long)fid; long sn = (long)vsn;
                    fref = (v & 0xFFFFFFFFFFFFUL) + "-" + (v >> 48);
                    vs = ((sn & 0xFFFFFFFFL) >> 16).ToString("X4") + "-" + (sn & 0xFFFF).ToString("X4");
                }
                long? its = Int(r.G("InstanceTimeStamp"));
                var fields = fref != null ? new List<Field> { new Field("FileRef", fref, Fmt.Raw(fid)), new Field("Volume serial", vs, Fmt.Raw(vsn)) }
                                          : new List<Field> { new Field("FileRef", "missing (FileID or VSN not an integer)", Fmt.Raw(fid) + " / " + Fmt.Raw(vsn)) };
                fields.Add(Tf("InstanceTimeStamp", its));
                foreach (var m in new[] { new object[] { "SHA1", "MD5", 16 }, new object[] { "MD5", "SHA1", 20 }, new object[] { "SHA256", "SHA256", 32 } })
                {
                    var d = r.G((string)m[0]) as byte[];
                    if (d == null) continue;
                    string h = Crypto.ToHex(d);
                    if (d.Length == (int)m[2]) fields.Add(new Field(m[1] + " (column " + m[0] + ")", h, h));
                    else fields.Add(new Field(m[1] + " (column " + m[0] + "; length " + d.Length + " ≠ " + m[2] + ", kept raw)", h, h));
                }
                foreach (var col in new[] { "USN", "LSHASH", "LSHASHS", "CTPH", "PartialCRC1", "PartialCRC2", "PartialCRC3", "KCRC1", "KCRC2", "KCRC3", "KCRC3n" })
                {
                    var v = r.G(col);
                    if (v == null) continue;
                    var b = v as byte[];
                    if (col == "CTPH" && b != null) fields.Add(new Field(col, Encoding.UTF8.GetString(b), Crypto.ToHex(b)));
                    else fields.Add(new Field(col, Fmt.Raw(v), Fmt.Raw(v)));
                }
                Push("FileHashed", Fmt.Plausible(its), fref != null ? "File hashed: MFT " + fref + " on " + vs : "File hashed: MFT reference missing", -1, fields, t, r, false);
            }
        }

        void LowFi(string t)
        {
            foreach (var r in Rows(t, new[] { "FileName", "InstanceTimeStamp" }, "LowFi"))
            {
                string path = Text(r.G("FileName")) ?? "";
                int loc = Location(path);
                var fields = new List<Field> { new Field("Path", path, path), Tf("InstanceTimeStamp", r.G("InstanceTimeStamp")) };
                var s = r.G("SigSha") as byte[]; if (s != null) fields.Add(new Field("Signature SHA", Crypto.ToHex(s), Crypto.ToHex(s)));
                var q = Int(r.G("SigSeq")); if (q.HasValue) fields.Add(new Field("SigSeq", q.ToString(), q.ToString()));
                Push("LowFiHit", Fmt.Plausible(Int(r.G("InstanceTimeStamp"))), "LowFi signature hit: " + Fmt.Leaf(path), loc, fields, t, r, false);
            }
        }

        void Amsi(string t)
        {
            foreach (var r in Rows(t, new[] { "PersistId", "ExpirationDate" }, "Store-cache expiry"))
            {
                string pid = Text(r.G("PersistId")) ?? "", exp = Text(r.G("ExpirationDate")) ?? "";
                long? parsed = Fmt.ParseTime(exp, 0);
                var fields = new List<Field> { new Field("PersistId (Store file name)", pid, pid), new Field("ExpirationDate", parsed.HasValue ? Fmt.Classified(parsed.Value, Tz) : exp, exp) };
                Push("StoreExpiry", Fmt.Plausible(parsed), "Store cache expiry: " + pid, -1, fields, t, r, false);
            }
        }

        void Reg(string t)
        {
            foreach (var r in Rows(t, new[] { "RegPath", "InstanceTimeStamp" }, "registry-cache"))
            {
                string path = Text(r.G("RegPath")) ?? "";
                long nt = Int(r.G("NewRegType")) ?? -1, ot = Int(r.G("OldRegType")) ?? -1;
                var nd = r.G("NewRegData") as byte[]; var od = r.G("OldRegData") as byte[];
                var fields = new List<Field> { new Field("RegPath", path, path), new Field("RegOperation", Fmt.EnumName("RegOperation", Int(r.G("RegOperation")) ?? -1), Fmt.Raw(r.G("RegOperation"))),
                    new Field("NewRegType", Fmt.RegTypeName(nt), nt.ToString()), new Field("NewRegData", nd != null ? Fmt.RegData(nt, nd) : "", Fmt.Raw(r.G("NewRegData"))),
                    new Field("OldRegType", Fmt.RegTypeName(ot), ot.ToString()), new Field("OldRegData", od != null ? Fmt.RegData(ot, od) : "", Fmt.Raw(r.G("OldRegData"))),
                    Tf("InstanceTimeStamp", r.G("InstanceTimeStamp")), new Field("FileIDHash", Fmt.Raw(r.G("FileIDHash")), Fmt.Raw(r.G("FileIDHash"))) };
                Push("RegistryChange", Fmt.Plausible(Int(r.G("InstanceTimeStamp"))), "Registry change: " + path, -1, fields, t, r, false);
            }
        }

        /// 'Tact-pid:<N>,ProcessStart:<FT>[-suffix]' (queues.rs tact + store.rs parse_pid_start).
        static bool Tact(string name, out ulong pid, out ulong start, out string suffix)
        {
            pid = 0; start = 0; suffix = "";
            if (!name.StartsWith("Tact-", StringComparison.Ordinal)) return false;
            string rest = name.Substring(5), s = rest.Trim();
            if (!s.StartsWith("pid:", StringComparison.Ordinal)) return false;
            s = s.Substring(4);
            int comma = s.IndexOf(',');
            if (comma < 0) return false;
            string pidS = s.Substring(0, comma), r2 = s.Substring(comma + 1);
            if (!r2.StartsWith("ProcessStart:", StringComparison.Ordinal)) return false;
            string digits = new string(r2.Substring(13).TakeWhile(ch => ch >= '0' && ch <= '9').ToArray());
            var p = Fmt.UInt(pidS, 32); var st = Fmt.UInt(digits, 64);
            int at = rest.IndexOf("ProcessStart:", StringComparison.Ordinal);
            if (!p.HasValue || !st.HasValue || at < 0) return false;
            string tail = rest.Substring(at + 13).TrimStart('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
            if (tail.Length > 0) { if (!tail.StartsWith("-") || tail.Length == 1) return false; suffix = tail.Substring(1); }
            pid = p.Value; start = st.Value;
            return true;
        }

        void Queues(string t)
        {
            foreach (var r in Rows(t, new[] { "EntryTable", "EntryKey", "EntryValue", "InsertTime" }, "rolling-queue"))
            {
                string qt = Text(r.G("EntryTable")) ?? "", key = Text(r.G("EntryKey")) ?? "", val = Text(r.G("EntryValue")) ?? "";
                long? ins = Int(r.G("InsertTime"));
                var fields = new List<Field> { new Field("Queue", qt, qt), new Field("Key", key, key), new Field("Value", val, val), Tf("InsertTime", ins), Tf("ExpireTime", r.G("ExpireTime")) };
                bool flag = false; int loc = -1;
                ulong pid, start; string suf;
                bool tq = Tact(qt, out pid, out start, out suf), tk = false;
                if (!tq) tk = Tact(key, out pid, out start, out suf);
                if (tq || tk)
                {
                    fields.Add(new Field("Process", "PID " + pid + " started " + (start <= long.MaxValue ? Fmt.Classified((long)start, Tz) : start + " (opaque)"), pid + "," + start));
                    if (suf != "") fields.Add(new Field("Counter set", suf, suf));
                    ulong p2, s2; string x2;
                    if (!Tact(key, out p2, out s2, out x2)) fields.Add(new Field(key, val, val));
                }
                else if (qt == "RecentThreatsOnMachine") { flag = true; fields.Add(new Field("Threat", key + " ×" + val, key)); }
                else if (qt == "domainInfo")
                {
                    if (key == "TCP-hostname") Host.Add(new HostFact { Label = "domainInfo hostname", Value = val, Table = t, Status = r.Status });
                    else
                    {
                        var parts = key.Split('.');
                        bool v4 = parts.Length == 4 && parts.All(o => Fmt.UInt(o, 8).HasValue);
                        var fl = Fmt.UInt(val.Trim(), 64);
                        if (key != "" && fl.HasValue)
                            Host.Add(new HostFact { Label = "domainInfo " + (v4 ? "ipv4" : "name"), Value = key + " (flags 0x" + fl.Value.ToString("x") + ", meaning unverified)", Table = t, Status = r.Status });
                        else fields.Add(new Field(key, val, val));
                    }
                }
                else if (qt == "RQ_RecentExecDropped" || qt == "RQ_RecentScriptDropped")
                {
                    loc = Location(key);
                    fields.Add(new Field(qt == "RQ_RecentScriptDropped" ? "Script dropped" : "Executable dropped", key, key));
                }
                else if (qt == "RDP-Event-Success")
                {
                    var logon = RdpParse(val);
                    if (logon != null)
                    {
                        ulong? lt = logon.Item1;
                        var g = logon.Item2;
                        var fl = new List<Field> { new Field("Source IP", g["Ip"], g["Ip"]), new Field("User SID", g["SLId"], g["SLId"]), new Field("Workstation", g["Wsn"], g["Wsn"]),
                            new Field("Session", g["TSid"], g["TSid"]), Tf("Logon time", lt.HasValue && lt.Value <= long.MaxValue ? (object)(long)lt.Value : null) };
                        Push("RdpLogon", lt.HasValue && lt.Value <= long.MaxValue ? Fmt.Plausible((long)lt.Value) : null, "RDP logon success from " + g["Ip"], -1, fl, t, r, true);
                    }
                    else fields.Add(new Field(key, val, val));
                }
                else if (qt.StartsWith("RDP-")) Host.Add(new HostFact { Label = qt, Value = key + "=" + val, Table = t, Status = r.Status });
                else if (qt == "KernelCallBackAddress" && key.StartsWith("fn_AddressRange") && ParseAddr(val).HasValue)
                {
                    ulong a = ParseAddr(val).Value; fields.Add(new Field(key, "0x" + a.ToString("x"), a.ToString()));
                }
                else fields.Add(new Field(key, val, val));
                Push("QueueEntry", Fmt.Plausible(ins), qt + ": " + key, loc, fields, t, r, flag);
            }
        }

        static ulong? ParseAddr(string s)
        {
            s = s.Trim();
            if (Regex.IsMatch(s, "^0[xX][0-9a-fA-F]{1,16}$")) return ulong.Parse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return Fmt.UInt(s, 64);
        }

        static bool JsonScalar(object v) { return v == null || v is string || v is int || v is long || v is decimal || v is double; }

        static ulong? JsonFt(object v)
        {
            if (v is int) return (int)v >= 0 ? (ulong?)(ulong)(int)v : null;
            if (v is long) return (long)v >= 0 ? (ulong?)(ulong)(long)v : null;
            if (v is decimal)
            {
                decimal d = (decimal)v;
                int scale = (decimal.GetBits(d)[3] >> 16) & 0xFF;
                return scale == 0 && d >= 0 && d <= 18446744073709551615m ? (ulong?)(ulong)d : null;
            }
            var s = v as string;
            return s != null ? Fmt.UInt(s.Trim(), 64) : null;
        }

        static string JsonStr(object v)
        {
            if (v == null) return "";
            if (v is string) return (string)v;
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        /// Strict JSON object of the RDP queue value -> (logon time, fields); null = not a logon record (decoded as Generic).
        static Tuple<ulong?, Dictionary<string, string>> RdpParse(string s)
        {
            object o;
            try { o = new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(s); }
            catch { return null; }
            var d = o as Dictionary<string, object>;
            if (d == null) return null;
            foreach (var k in new[] { "Wsn", "SLId", "Ip", "TSid", "LT" }) if (d.ContainsKey(k) && !JsonScalar(d[k])) return null;
            ulong? lt = null;
            if (d.ContainsKey("LT")) { lt = JsonFt(d["LT"]); if (!lt.HasValue) return null; }
            var f = new Dictionary<string, string>();
            foreach (var k in new[] { "Wsn", "SLId", "Ip", "TSid" }) f[k] = d.ContainsKey(k) ? JsonStr(d[k]) : "";
            return Tuple.Create(lt, f);
        }

        static readonly Dictionary<string, string> KnownFolders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            {"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}","Desktop"},{"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}","Documents"},{"{374DE290-123F-4565-9164-39C4925E467B}","Downloads"},
            {"{4BD8D571-6D19-48D3-BE97-422220080E43}","Music"},{"{33E28130-4E1E-4676-835A-98395C3BC3BB}","Pictures"},{"{18989B1D-99B5-455B-841C-AB7C74E4DDFC}","Videos"},
            {"{1777F761-68AD-4D8A-87BD-30B759FA33DD}","Favorites"},{"{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}","Public Desktop"},{"{ED4824AF-DCE4-45A8-81E2-FC7965083634}","Public Documents"},
            {"{3214FAB5-9757-4298-BB61-92A9DEAA44FF}","Public Music"},{"{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}","Public Pictures"},{"{2400183A-6185-49FB-A2D8-4A392A602BA3}","Public Videos"}};

        void Cfa(string t)
        {
            foreach (var r in All(t))
            {
                string sid = Text(r.G("UserId")) ?? "";
                var gb = r.G("GUID") as byte[];
                string guid = gb != null ? (Fmt.Guid(gb) ?? "") : "";
                string name; if (!KnownFolders.TryGetValue(guid, out name)) name = guid;
                string path = Text(r.G("Path")) ?? "";
                Host.Add(new HostFact { Label = "CFA protected folder (" + sid + ")", Value = path != "" ? name + " (" + path + ")" : name, Table = t, Status = r.Status });
            }
        }

        void HostRows(string t)
        {
            var cols = Tables[t].Columns;
            foreach (var r in All(t))
            {
                if (t == "SQLiteGlobals")
                    Host.Add(new HostFact { Label = "SQLite schema version", Value = Fmt.Raw(r.G("Version")) + " (current " + Fmt.Raw(r.G("Current")) + ", updated " + Fmt.Raw(r.G("LastUpdated")) + ")", Table = t, Status = r.Status });
                else Host.Add(new HostFact { Label = t, Value = string.Join(", ", cols.Zip(r.V, (n, v) => n + "=" + Fmt.Raw(v))), Table = t, Status = r.Status });
            }
        }

        void Bm(string t)
        {
            var idx = Cols(t); var cols = Tables[t].Columns;
            string timeCol = new[] { "ProcessStartTime", "TimeStamp", "DetectionTS", "LkgTS", "RemedComplTS", "InstanceTimeStamp" }.FirstOrDefault(x => idx.ContainsKey(x.ToLowerInvariant()));
            string pathCol = new[] { "ImageFileName", "ProcessPath", "FilePath", "NormalizedPath", "DosPath", "SystemFilePath" }.FirstOrDefault(x => idx.ContainsKey(x.ToLowerInvariant()));
            foreach (var r in All(t))
            {
                long? tm = timeCol != null ? Fmt.Plausible(Int(r.G(timeCol))) : null;
                string path = (pathCol != null ? Text(r.G(pathCol)) : null) ?? "";
                int loc = Location(path);
                var fields = cols.Zip(r.V, (n, v) => { var c = Fmt.Cell(n, v, Tz); return new Field(n, c[0], c[1]); }).ToList();
                Push("BmRecord", tm, t + ": " + Fmt.Leaf(path), loc, fields, t, r, false);
            }
        }

        // ---------------------------------------------------------------- findings, filters, search
        public static bool SpecialOk(Event e, string special)
        {
            if (special == "renamed_exe") return (e.Kind == "OfnSet" || e.Kind == "OfnSetInferred") && e.F("Rename kind") == "executable rename";
            if (special == "detections") return (e.Kind == "QueueEntry" && e.F("Threat") != null) || e.Kind == "LowFiHit";
            return true;
        }

        public List<Card> Findings()
        {
            var o = new List<Card>();
            Action<string, string, string, Func<Event, bool>> add = (level, title, explain, pred) =>
            {
                var c = new Card { Level = level, Title = title, Explain = explain, Ids = new HashSet<int>(), Examples = new List<string>() };
                foreach (var e in Events) if (pred(e))
                    {
                        c.Ids.Add(e.Id);
                        if (c.Examples.Count < 3 && e.Loc >= 0) { var n = Fmt.Leaf(Locations[e.Loc].Spellings[0]); if (n != "" && !c.Examples.Contains(n)) c.Examples.Add(n); }
                    }
                o.Add(c);
            };
            add("flag", "Unsigned programs run outside system folders", "First run of a binary with no embedded certificate, not under Windows or Program Files.", e => e.Kind == "NoCertExec" && Cls(e.Loc) == "outside system dirs");
            add("flag", "Renamed executables outside system folders", "The file's OriginalFileName (set at creation) differs from its name, e.g. a copied robocopy.exe renamed.",
                e => SpecialOk(e, "renamed_exe") && Cls(e.Loc) == "outside system dirs");
            add("flag", "Threat detections", "Behaviour or signature detections Defender keeps in its recent-threats queue.", e => e.Kind == "QueueEntry" && e.F("Threat") != null);
            add("flag", "RDP logons", "Successful inbound RDP logons recorded by Defender (source IP, user, workstation).", e => e.Kind == "RdpLogon");
            add("flag", "Rows found only in the WAL (or deleted by it)", "Newest activity not yet written into the main database, and rows the WAL removed. (Changed rows: Found only in the WAL view.)", e => e.Status == "WAL-only" || e.Status == "Removed by WAL");
            add("info", "Programs started", "First start of each program in Defender's ~7-day window (time = process creation).", e => e.Kind == "ProcessFirstStart");
            add("info", "All unsigned program runs", "Every first run of a binary without an embedded certificate, including system folders.", e => e.Kind == "NoCertExec");
            add("info", "Signature hits (low-fidelity)", "Files that matched a low-fidelity signature and were sent for a closer look.", e => e.Kind == "LowFiHit");
            add("info", "File hashes", "MD5 / SHA1 / SHA256 of files Defender hashed, by MFT reference.", e => e.Kind == "FileHashed" && !(e.F("FileRef") ?? "").StartsWith("missing"));
            add("info", "Behaviour-monitor records", "Rows from the behaviour-monitoring, ransomware, process-block and system-file tables.", e => e.Kind == "BmRecord");
            add("info", "Registry changes", "Registry values Defender backed up with old and new data.", e => e.Kind == "RegistryChange");
            return o;
        }

        public static List<KeyValuePair<string, Facets>> QuickViews()
        {
            Func<string[], HashSet<string>> k = a => new HashSet<string>(a);
            return new List<KeyValuePair<string, Facets>> {
                new KeyValuePair<string, Facets>("All activity", new Facets()),
                new KeyValuePair<string, Facets>("Red flags", new Facets { Flagged = true }),
                new KeyValuePair<string, Facets>("Programs run", new Facets { Kinds = k(new[] { "ProcessFirstStart", "NoCertExec" }) }),
                new KeyValuePair<string, Facets>("Unsigned programs", new Facets { Kinds = k(new[] { "NoCertExec" }) }),
                new KeyValuePair<string, Facets>("Renamed executables", new Facets { Special = "renamed_exe" }),
                new KeyValuePair<string, Facets>("Detections & signatures", new Facets { Special = "detections" }),
                new KeyValuePair<string, Facets>("Found only in the WAL", new Facets { Status = new HashSet<string>(WalStatuses) }) };
        }

        /// One search term: Test judges an event; Cell (free text and /regex/ only) judges the text a grid row shows.
        public class Term { public bool Neg; public Func<Event, bool> Test; public Func<string[], bool> Cell; }

        /// Glob with * and ?; without a wildcard: case-insensitive substring (query Glob semantics).
        static Func<string, bool> Matcher(string pat)
        {
            string p = pat.ToLowerInvariant();
            if (p.Contains("*") || p.Contains("?"))
            {
                var rx = new Regex("^" + Regex.Escape(p).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.Singleline);
                return s => rx.IsMatch(s.ToLowerInvariant());
            }
            return s => s.ToLowerInvariant().Contains(p);
        }

        static readonly Dictionary<string, string> SrcKeys = new Dictionary<string, string> {
            { "db", "DB" }, { "wal", "WAL-only" }, { "walonly", "WAL-only" }, { "walmod", "WAL-modified" }, { "walmodified", "WAL-modified" },
            { "removed", "Removed by WAL" }, { "removedbywal", "Removed by WAL" }, { "unknown", "unknown" } };
        static readonly Dictionary<string, string> LocKeys = new Dictionary<string, string> { { "system", "system dir" }, { "outside", "outside system dirs" }, { "unknown", "unknown" } };
        static readonly string[] SearchKeys = { "path", "name", "sha256", "sha1", "md5", "pid", "type", "src", "loc", "nocert", "after", "before" };

        public class Tok { public bool Neg; public string Text; public string Kind; }

        /// Tokens with Kind "plain" (may be key:value), "regex" (/.../) or "literal" (a quote opened before any ':', so free
        /// text even if it looks like key:value). Double quotes group words, also after key: (path:"C:\Program Files\*");
        /// a /regex/ runs to the next '/' followed by whitespace or the end (as the exe).
        public static List<Tok> SearchTokens(string q)
        {
            q = q ?? "";
            var o = new List<Tok>(); int i = 0, n = q.Length;
            while (i < n)
            {
                if (char.IsWhiteSpace(q[i])) { i++; continue; }
                bool neg = false;
                if (q[i] == '-' && i + 1 < n && !char.IsWhiteSpace(q[i + 1])) { neg = true; i++; }
                if (q[i] == '/')
                {
                    int j = -1;
                    for (int x = i + 1; x < n; x++) if (q[x] == '/' && (x + 1 == n || char.IsWhiteSpace(q[x + 1]))) { j = x; break; }
                    if (j >= 0) { o.Add(new Tok { Neg = neg, Text = q.Substring(i + 1, j - i - 1), Kind = "regex" }); i = j + 1; continue; }
                }
                var sb = new StringBuilder(); bool quoted = false, keySeen = false; string kind = "plain";
                while (i < n && (quoted || !char.IsWhiteSpace(q[i])))
                {
                    char ch = q[i];
                    if (ch == '"') { if (!keySeen) kind = "literal"; quoted = !quoted; }
                    else { if (ch == ':') keySeen = true; sb.Append(ch); }
                    i++;
                }
                if (quoted) throw new Exception("unterminated quote");
                o.Add(new Tok { Neg = neg, Text = sb.ToString(), Kind = kind });
            }
            return o;
        }

        /// Process ID an event observes (Tact queue 'Process' fact, BmProcessInfo PID), as the exe's process observations.
        public static long? PidOf(Event e)
        {
            if (e.Kind == "QueueEntry")
            {
                foreach (var f in e.Fields) if (f.Name == "Process") { long v; if (long.TryParse(f.Raw.Split(',')[0], out v)) return v; }
            }
            else if (e.Kind == "BmRecord" && e.Table == "BmProcessInfo")
            {
                foreach (var f in e.Fields) if (f.Name == "PID") { long v; if (long.TryParse(f.Raw, out v) && v >= 0 && v <= uint.MaxValue) return v; return null; }
            }
            return null;
        }

        HashSet<int> nocertLocs;

        public List<Term> ParseSearch(string q)
        {
            var terms = new List<Term>();
            foreach (var tk in SearchTokens(q))
            {
                bool neg = tk.Neg; string t = tk.Text;
                if (tk.Kind == "regex")
                {
                    Regex rx;
                    try { rx = new Regex(t, RegexOptions.IgnoreCase); }
                    catch (Exception e) { throw new Exception("bad regular expression: " + e.Message); }
                    terms.Add(new Term { Neg = neg, Test = e => rx.IsMatch(e.Text), Cell = cells => cells.Any(c => c != null && rx.IsMatch(c)) }); continue;
                }
                var m = tk.Kind == "plain" ? Regex.Match(t, "^([A-Za-z0-9]+):(.*)$", RegexOptions.Singleline) : Match.Empty;
                if (!m.Success || !SearchKeys.Contains(m.Groups[1].Value.ToLowerInvariant()))
                {
                    string s = t.ToLowerInvariant();
                    terms.Add(new Term { Neg = neg, Test = e => e.Text.Contains(s), Cell = cells => cells.Any(c => c != null && c.ToLowerInvariant().Contains(s)) }); continue;
                }
                string k = m.Groups[1].Value.ToLowerInvariant(), v = m.Groups[2].Value, vl = v.ToLowerInvariant();
                if (v == "") throw new Exception(k + ": needs a value");
                Func<Event, bool> test;
                if (k == "after" || k == "before")
                {
                    var ft = Fmt.ParseTime(v, Tz);
                    if (!ft.HasValue) throw new Exception(k + ":" + v + " is not a date (use YYYY-MM-DD or YYYY-MM-DD HH:MM)");
                    long f = ft.Value;
                    if (k == "after") test = e => e.Time.HasValue && e.Time.Value >= f;
                    else test = e => e.Time.HasValue && e.Time.Value <= f;
                }
                else if (k == "path")
                {
                    var g = Matcher(v);
                    test = e => e.Loc >= 0 && (g(Locations[e.Loc].Key) || Locations[e.Loc].Spellings.Any(g));
                }
                else if (k == "name")
                {
                    var g = Matcher(v);
                    test = e => { if (e.Loc < 0) return false; var key = Locations[e.Loc].Key; return g(key.Substring(key.LastIndexOf('\\') + 1)); };
                }
                else if (DigestFields.ContainsKey(k))
                {
                    // no wildcard: a prefix, as the exe
                    var g = Matcher(v.Contains("*") || v.Contains("?") ? v : v + "*"); string lab = DigestFields[k];
                    test = e => e.Kind == "FileHashed" && !(e.F("FileRef") ?? "").StartsWith("missing") && e.Fields.Any(f => f.Name == lab && g(f.Display));
                }
                else if (k == "pid")
                {
                    long pid;
                    if (!Regex.IsMatch(v, "^[0-9]+$") || !long.TryParse(v, out pid) || pid > uint.MaxValue) throw new Exception("pid:" + v + " is not a number");
                    test = e => PidOf(e) == pid;
                }
                else if (k == "type")
                {
                    var g = Matcher(v);
                    test = e => g(e.Kind) || g(KindLabel[e.Kind]);
                }
                else if (k == "src")
                {
                    string want;
                    if (!SrcKeys.TryGetValue(vl.Replace("-", "").Replace(" ", ""), out want)) throw new Exception("src:" + v + " — use db, walonly, walmod, removed, unknown");
                    test = e => e.Status == want;
                }
                else if (k == "loc")
                {
                    string want;
                    if (!LocKeys.TryGetValue(vl, out want)) throw new Exception("loc:" + v + " — use system, outside, unknown");
                    test = e => Cls(e.Loc) == want;
                }
                else
                {
                    if (vl != "yes") throw new Exception("nocert: takes only 'yes'");
                    test = e =>
                    {
                        if (nocertLocs == null) nocertLocs = new HashSet<int>(Events.Where(x => x.Kind == "NoCertExec" && x.Loc >= 0).Select(x => x.Loc));
                        return e.Loc >= 0 && nocertLocs.Contains(e.Loc);
                    };
                }
                terms.Add(new Term { Neg = neg, Test = test });
            }
            return terms;
        }

        /// Events matching filters and search, oldest first (untimed last). Routine types are hidden from broad lists only:
        /// a search, a type filter, an event set, a quick-view predicate, red flags or a WAL status shows its routine matches too.
        public List<Event> Apply(Facets f, List<Term> terms, bool showRoutine)
        {
            var kinds = f.Kinds;
            bool targeted = f.Only != null || f.Special != null || f.Flagged || f.Status != null || terms.Count > 0;
            if (kinds == null && !showRoutine && !targeted) kinds = new HashSet<string>(KindLabel.Keys.Where(x => !Routine.Contains(x)));
            var o = new List<Event>();
            foreach (var e in Events)
            {
                if (f.Only != null && !f.Only.Contains(e.Id)) continue;
                if (kinds != null && !kinds.Contains(e.Kind)) continue;
                if (f.Status != null && !f.Status.Contains(e.Status)) continue;
                if (f.Cls != null && !f.Cls.Contains(Cls(e.Loc))) continue;
                if (f.Flagged && !e.Flag) continue;
                if (!SpecialOk(e, f.Special)) continue;
                bool ok = true;
                foreach (var t in terms) if (t.Test(e) == t.Neg) { ok = false; break; }
                if (ok) o.Add(e);
            }
            return Sorted(o);
        }

        /// The events a Files & processes row stands for: its own event, or every event at a location (Locations view).
        public List<Event> RowEvents(View v, int i)
        {
            if (v.Events != null) return i < v.Events.Count ? new List<Event> { v.Events[i] } : new List<Event>();
            if (v.Name == "Locations" && i < Locations.Count) return Locations[i].Events.Select(x => Events[x]).ToList();
            return new List<Event>();
        }

        /// Rows of a Files & processes view kept by the search. A query with structured terms (path:, sha256:, type:, ...) is
        /// judged on the row's events exactly as the Timeline does; rows without events cannot satisfy it. A free-text /
        /// regex query is judged term by term on the row's events and on the text shown in its cells. Unparsable: substring.
        public List<int> FilterView(View v, string q)
        {
            q = (q ?? "").Trim();
            var keep = new List<int>();
            if (q == "") { for (int i = 0; i < v.Rows.Count; i++) keep.Add(i); return keep; }
            List<Term> terms;
            try { terms = ParseSearch(q); }
            catch { return Ui.Filter(v.Rows, q); }
            bool structured = terms.Any(t => t.Cell == null);
            var ids = structured ? new HashSet<int>(Apply(new Facets(), terms, true).Select(e => e.Id)) : null;
            for (int i = 0; i < v.Rows.Count; i++)
            {
                var es = RowEvents(v, i); var cells = v.Rows[i];
                bool ok = structured ? es.Any(e => ids.Contains(e.Id)) : terms.All(t => (t.Cell(cells) || es.Any(e => t.Test(e))) != t.Neg);
                if (ok) keep.Add(i);
            }
            return keep;
        }

        public static List<Event> Sorted(IEnumerable<Event> es) { return es.OrderBy(e => e.Time.HasValue ? 0 : 1).ThenBy(e => e.Time ?? 0).ToList(); }

        public string Details(Event e)
        {
            string lab = KindLabel[e.Kind], nm = Fmt.Leaf(PathOf(e));
            string d = e.Summary.StartsWith(lab + ": ") ? e.Summary.Substring(lab.Length + 2) : e.Summary;
            return nm != "" && d.Equals(nm, StringComparison.OrdinalIgnoreCase) ? "" : d;
        }

        // ---------------------------------------------------------------- views, evidence, export
        public class View { public string Name; public string[] Columns; public List<string[]> Rows = new List<string[]>(); public List<Event> Events; }

        View EvView(string name, string[] kinds, string[] cols, Func<Event, string>[] fns)
        {
            var v = new View { Name = name, Columns = cols, Events = Sorted(Events.Where(e => kinds.Contains(e.Kind))) };
            foreach (var e in v.Events) v.Rows.Add(fns.Select(f => f(e) ?? "").ToArray());
            return v;
        }

        public List<View> Views()
        {
            Func<Event, string> T = e => TimeStr(e.Time), P = PathOf, N = e => Fmt.Leaf(PathOf(e)), S = e => e.Status, L = e => Cls(e.Loc);
            Func<string, Func<Event, string>> F = n => (e => e.F(n) ?? "");
            var o = new List<View> {
                EvView("Process runs", new[]{"ProcessFirstStart"}, new[]{"First start","Image","Location","Path","NextUSN","Source"}, new[]{T,N,L,P,F("NextUSN"),S}),
                EvView("No-cert executions", new[]{"NoCertExec"}, new[]{"Inserted","File","Location","Path","Source"}, new[]{T,N,L,P,S}),
                EvView("Renamed binaries (OFN)", new[]{"OfnSet","OfnSetInferred"}, new[]{"Inserted","File","OriginalFileName","Rename kind","Rule","Location","Path","Source"},
                    new[]{T,N,F("OriginalFileName"),F("Rename kind"),e=>KindLabel[e.Kind],L,P,S}),
                EvView("Module loads", new[]{"ModuleFirstLoad"}, new[]{"Recorded","Module","Path","Source"}, new[]{T,N,P,S}),
                EvView("File content & hashes", new[]{"FileHashed"}, new[]{"Hashed","FileRef","Volume","SHA256","SHA1","MD5","Source"},
                    new[]{T,F("FileRef"),F("Volume serial"),F("SHA256 (column SHA256)"),F("SHA1 (column MD5)"),F("MD5 (column SHA1)"),S}),
                EvView("Defender file contexts", new[]{"FileContext","OfnProcessed"}, new[]{"Inserted","Context","Engine tag","Path","Source"}, new[]{T,F("Context"),F("Engine tag"),P,S}),
                EvView("LowFi hits", new[]{"LowFiHit"}, new[]{"Time","Path","Signature SHA (not a file hash)","SigSeq","Source"}, new[]{T,P,F("Signature SHA"),F("SigSeq"),S}),
                EvView("Queues", new[]{"QueueEntry"}, new[]{"Inserted","Queue","Key","Value","Expires","Source"}, new[]{T,F("Queue"),F("Key"),F("Value"),F("ExpireTime"),S}),
                EvView("RDP", new[]{"RdpLogon"}, new[]{"Logon","Source IP","User SID","Workstation","Session","Source"}, new[]{T,F("Source IP"),F("User SID"),F("Workstation"),F("Session"),S}),
                EvView("Registry cache", new[]{"RegistryChange"}, new[]{"Time","Key","Operation","New type","New data","Old type","Old data","Source"},
                    new[]{T,F("RegPath"),F("RegOperation"),F("NewRegType"),F("NewRegData"),F("OldRegType"),F("OldRegData"),S}),
                EvView("Behaviour monitor", new[]{"BmRecord"}, new[]{"Time","Table","Name","Path","Source"}, new[]{T,e=>e.Table,N,P,S}),
                EvView("Store cache (AMSI)", new[]{"StoreExpiry"}, new[]{"Expires","Store file name","Source"}, new[]{T,F("PersistId (Store file name)"),S}) };
            var h = new View { Name = "Host context", Columns = new[] { "Fact", "Value", "Table", "Source" } };
            foreach (var x in Host) h.Rows.Add(new[] { x.Label, x.Value, x.Table, x.Status });
            o.Add(h);
            var l = new View { Name = "Locations", Columns = new[] { "Path", "Class", "Events", "Spellings" } };
            foreach (var x in Locations) l.Rows.Add(new[] { x.Spellings[0], x.Cls, x.Events.Count.ToString(), x.Spellings.Count.ToString() });
            o.Add(l);
            return o;
        }

        public View RawView(string t)
        {
            var tp = Tables[t];
            var cols = (tp.Columns ?? new string[0]).ToList();
            string src = "Source";  // provenance column; bracketed until it no longer clashes with a table column of that name
            while (cols.Any(c => string.Equals(c, src, StringComparison.OrdinalIgnoreCase))) src = "[" + src + "]";
            var v = new View { Name = t, Columns = cols.Concat(new[] { src }).ToArray() };
            foreach (var r in tp.Rows)
            {
                var row = new string[cols.Count + 1];
                for (int i = 0; i < cols.Count; i++) row[i] = i < r.Values.Length ? Fmt.Cell(cols[i], r.Values[i], Tz)[0] : "";
                row[cols.Count] = r.Status;
                v.Rows.Add(row);
            }
            return v;
        }

        public string EvidenceText()
        {
            var w = Img.Wal; var sb = new StringBuilder();
            string stop = !w.Present ? "no WAL file" : !w.HeaderValid ? "WAL header invalid — WAL not applied" : (w.Stop ?? "none — checksum chain fully validated");
            sb.AppendLine("mpdbx (PowerShell edition) 2.0").AppendLine().AppendLine("Inputs");
            foreach (var i in Inputs) sb.AppendLine("  " + i[0]).AppendLine("    " + i[1] + " bytes   SHA256 " + i[2] + "   modified " + i[3]);
            sb.AppendLine().AppendLine("Database and WAL");
            sb.AppendLine("  Page size / pages              " + Img.PageSize + " / " + Img.Pages);
            sb.AppendLine("  Encrypted                      " + Img.Encrypted + "  (built-in mpengine key)");
            sb.AppendLine("  Header bytes 18-19             [" + Img.H18 + ", " + Img.H19 + "]  (2,2 = WAL mode; loaded as a rollback-journal copy)");
            sb.AppendLine("  WAL present / header valid     " + w.Present + " / " + w.HeaderValid);
            sb.AppendLine("  WAL frames total/valid/applied " + w.FramesTotal + " / " + w.FramesValid + " / " + w.FramesApplied);
            sb.AppendLine("  WAL commits applied            " + w.Commits);
            sb.AppendLine("  Frames after the last commit   " + w.IgnoredTail + " (ignored)");
            sb.AppendLine("  WAL stop                       " + stop);
            sb.AppendLine("  WAL salts                      0x" + w.Salt1.ToString("x8") + " 0x" + w.Salt2.ToString("x8"));
            sb.AppendLine().AppendLine("  " + "Table".PadRight(32) + "DB-only".PadLeft(9) + "Merged".PadLeft(9) + "WAL-only".PadLeft(10) + "WAL-mod".PadLeft(9) + "Removed".PadLeft(9));
            foreach (var t in Tables.Keys.OrderBy(x => x, StringComparer.Ordinal))
            {
                var tp = Tables[t];
                Func<string, int> cnt = s => tp.Rows.Count(r => r.Status == s);
                sb.AppendLine("  " + t.PadRight(32) + (tp.DbOnly.HasValue ? tp.DbOnly.ToString() : "None").PadLeft(9) + (tp.Merged.HasValue ? tp.Merged.ToString() : "None").PadLeft(9) +
                              cnt("WAL-only").ToString().PadLeft(10) + cnt("WAL-modified").ToString().PadLeft(9) + cnt("Removed by WAL").ToString().PadLeft(9));
            }
            if (Warnings.Count > 0) { sb.AppendLine().AppendLine("Warnings"); foreach (var x in Warnings) sb.AppendLine("  " + x); }
            sb.AppendLine().Append("Volume map (inferred): ").AppendLine(VolMap.Count == 0 ? "none" : string.Join(", ", VolMap.OrderBy(x => x.Key).Select(x => "HarddiskVolume" + x.Key + " = " + x.Value + ":")));
            return sb.ToString();
        }

        public static readonly string[] TimelineCols = { "Time", "Type", "Summary", "Path", "Source", "Flag", "raw_time", "prov_source", "prov_key", "prov_status" };

        public List<string[]> TimelineRows(IEnumerable<Event> es)
        {
            return es.Select(e => new[] { e.Time.HasValue ? TimeStr(e.Time) : "", KindLabel[e.Kind], e.Summary, PathOf(e), e.Status, e.Flag ? "▲" : "",
                e.Time.HasValue ? e.Time.Value.ToString() : "", e.Table, KeyLabel(e.Key), e.Status }).ToList();
        }

        static string Csv(string s) { s = s ?? ""; return s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s; }

        public void WriteCsv(string path, string[] cols, IEnumerable<string[]> rows)
        {
            Guard.Check(path, Inputs.Select(i => i[0]));
            using (var w = new StreamWriter(path, false, new UTF8Encoding(true)))
            {
                w.NewLine = "\r\n";
                w.WriteLine(string.Join(",", cols.Select(Csv)));
                foreach (var r in rows) w.WriteLine(string.Join(",", r.Select(Csv)));
            }
        }

        public int ExportAll(string dir)
        {
            Directory.CreateDirectory(dir);
            string root = System.IO.Path.GetFullPath(dir).TrimEnd('\\');
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ins = Inputs.Select(i => i[0]).ToList();
            // sanitised names can collide ("a:b", "a?b", "A:B"): suffix _2, _3 ... case-insensitively (as the exe)
            Func<string, string, string> dest = (stem, ext) =>
            {
                string name = Guard.SafeName(stem + ext); int k = 2;
                while (!used.Add(name)) { name = Guard.SafeName(stem + "_" + k + ext); k++; }
                string p = System.IO.Path.Combine(dir, name);
                if (!string.Equals(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(p)).TrimEnd('\\'), root, StringComparison.OrdinalIgnoreCase))
                    throw new Exception("export file would leave the output folder: " + stem + ext);
                Guard.Check(p, ins);
                return p;
            };
            var jobs = new List<Tuple<string, string[], List<string[]>>>();
            jobs.Add(Tuple.Create(dest("Timeline", ".csv"), TimelineCols, TimelineRows(Sorted(Events))));
            foreach (var v in Views()) jobs.Add(Tuple.Create(dest(v.Name, ".csv"), v.Columns, v.Rows));
            foreach (var t in Tables.Keys) { var v = RawView(t); jobs.Add(Tuple.Create(dest("raw_" + t, ".csv"), v.Columns, v.Rows)); }
            string ev = dest("evidence", ".txt");
            // every target passed the guard: only now is anything written
            foreach (var j in jobs) WriteCsv(j.Item1, j.Item2, j.Item3);
            File.WriteAllText(ev, EvidenceText(), new UTF8Encoding(false));
            return jobs.Count + 1;
        }
    }
}
