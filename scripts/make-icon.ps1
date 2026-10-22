# Regenerates assets\netattrib.ico (16-256 px, embedded by build.rs) and assets\netattrib.png
# (the window icon):
#   powershell -ExecutionPolicy Bypass -File scripts\make-icon.ps1 -OutDir assets
param([Parameter(Mandatory)][string]$OutDir)
# netattrib icon: a process tile fanning out to three remote endpoints, on a blue tile.
# Drawn natively at every size (no downscaling) so 16-24 px stay crisp.
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function New-IconPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 256.0

    # Background: rounded square with a diagonal gradient.
    $m = [Math]::Max(0.5, 12 * $s); $r = 52 * $s
    $rect = New-Object System.Drawing.RectangleF $m, $m, ($size - 2 * $m), ($size - 2 * $m)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc($rect.Right - $d, $rect.Y, $d, $d, 270, 90)
    $path.AddArc($rect.Right - $d, $rect.Bottom - $d, $d, $d, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect,
        ([System.Drawing.Color]::FromArgb(255, 29, 78, 216)),
        ([System.Drawing.Color]::FromArgb(255, 8, 145, 178)), 45.0
    $g.FillPath($bg, $path)

    $white = [System.Drawing.Color]::White
    # Small sizes get relatively heavier strokes so the glyph survives.
    $lineW = [Math]::Max(12 * $s, 1.4)
    $dotR = [Math]::Max(20 * $s, 1.9)
    $pen = New-Object System.Drawing.Pen $white, $lineW
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $fill = New-Object System.Drawing.SolidBrush $white

    # Process tile (left) and its three endpoints (right).
    $tx = 50 * $s; $ty = 94 * $s; $tw = 72 * $s
    $from = New-Object System.Drawing.PointF ($tx + $tw), ($ty + $tw / 2)
    $ends = @(@(196, 70), @(208, 128), @(196, 186))
    foreach ($e in $ends) {
        $to = New-Object System.Drawing.PointF ($e[0] * $s), ($e[1] * $s)
        $g.DrawLine($pen, $from, $to)
    }
    foreach ($e in $ends) {
        $g.FillEllipse($fill, ($e[0] * $s - $dotR), ($e[1] * $s - $dotR), (2 * $dotR), (2 * $dotR))
    }
    $tr = [Math]::Max(14 * $s, 1)
    $tile = New-Object System.Drawing.Drawing2D.GraphicsPath
    $td = 2 * $tr
    $tile.AddArc($tx, $ty, $td, $td, 180, 90)
    $tile.AddArc($tx + $tw - $td, $ty, $td, $td, 270, 90)
    $tile.AddArc($tx + $tw - $td, $ty + $tw - $td, $td, $td, 0, 90)
    $tile.AddArc($tx, $ty + $tw - $td, $td, $td, 90, 90)
    $tile.CloseFigure()
    $g.FillPath($fill, $tile)
    if ($size -ge 32) {
        # A title bar on the tile, in the background colour, from 32 px up.
        $bar = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 29, 78, 216))
        $g.FillRectangle($bar, ($tx + 12 * $s), ($ty + 14 * $s), ($tw - 24 * $s), [Math]::Max(10 * $s, 1.5))
    }
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$pngs = @{}
foreach ($z in $sizes) { $pngs[$z] = New-IconPng $z }

# ICO container: ICONDIR, one ICONDIRENTRY per size, then the PNG images.
$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $out
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($z in $sizes) {
    $b = if ($z -ge 256) { 0 } else { $z }
    $w.Write([Byte]$b); $w.Write([Byte]$b); $w.Write([Byte]0); $w.Write([Byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$pngs[$z].Length); $w.Write([UInt32]$offset)
    $offset += $pngs[$z].Length
}
foreach ($z in $sizes) { $w.Write($pngs[$z]) }
$w.Flush()
New-Item -ItemType Directory -Force $OutDir | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $OutDir 'netattrib.ico'), $out.ToArray())
[System.IO.File]::WriteAllBytes((Join-Path $OutDir 'netattrib.png'), $pngs[256])
"ico {0} bytes, png {1} bytes" -f $out.Length, $pngs[256].Length
