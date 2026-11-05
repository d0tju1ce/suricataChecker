using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace SuricataChecker
{
    /// <summary>Logo "suCH" in Nunito Sans ExtraBold: black square with white text in the app, side bar orange with black text in the exe icon; slightly rounded corners.</summary>
    static class Logo
    {
        public const string Mark = "suCH";

        public static void Draw(Graphics g, RectangleF r, FontFamily family) => Draw(g, r, family, Color.Black, Color.White);

        public static void Draw(Graphics g, RectangleF r, FontFamily family, Color background, Color foreground)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            using (var box = Theme.Round(r, r.Width * 0.12f))
                using (var b = new SolidBrush(background)) g.FillPath(b, box);

            using (var text = new GraphicsPath())
            {
                text.AddString(Mark, family, (int)FontStyle.Regular, 100f, PointF.Empty, StringFormat.GenericTypographic);
                var tb = text.GetBounds();
                float scale = r.Width * (r.Width <= 24 ? 0.84f : 0.68f) / tb.Width;
                using (var m = new Matrix())
                {
                    m.Translate(r.X + (r.Width - tb.Width * scale) / 2 - tb.X * scale,
                                r.Y + (r.Height - tb.Height * scale) / 2 - tb.Y * scale);
                    m.Scale(scale, scale);
                    text.Transform(m);
                }
                using (var b = new SolidBrush(foreground)) g.FillPath(b, text);
            }
        }

        public static Bitmap Render(int size, FontFamily family)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                Draw(g, new RectangleF(0, 0, size, size), family, Theme.Sidebar, Theme.SidebarText);
            }
            return bmp;
        }

        /// <summary>Writes app.ico (16–256 px) and PNG logos – run as: SuricataChecker-&lt;version&gt;.exe --export-logo &lt;dir&gt;</summary>
        public static void Export(string dir, FontFamily family)
        {
            Directory.CreateDirectory(dir);
            var images = new List<byte[]>();
            int[] sizes = { 16, 20, 24, 32, 40, 48, 64, 128, 256 };
            foreach (int size in sizes)
                using (var bmp = Render(size, family))
                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, ImageFormat.Png);
                    images.Add(ms.ToArray());
                }
            using (var fs = File.Create(Path.Combine(dir, "app.ico")))
            using (var w = new BinaryWriter(fs))
            {
                w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i])); w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                    w.Write((byte)0); w.Write((byte)0); w.Write((short)1); w.Write((short)32);
                    w.Write(images[i].Length); w.Write(offset);
                    offset += images[i].Length;
                }
                foreach (var img in images) w.Write(img);
            }
            foreach (int size in new[] { 256, 512, 1024 })
                using (var bmp = Render(size, family)) bmp.Save(Path.Combine(dir, $"{Program.AppName}-logo-{size}.png"), ImageFormat.Png);
        }
    }
}
