# MyPC LAN & Print Doctor

**MyPC LAN & Print Doctor v1.1 (P1.1)** — chẩn đoán và khắc phục có kiểm soát lỗi LAN / chia sẻ máy in trên Windows 10/11.

Phát triển bởi [MyPC Việt Nam](https://mypc.vn).

## Mục tiêu

Giải quyết các tình huống văn phòng thực tế:

- Máy trạm không ping được máy chủ in (IP server không đổi)
- Windows Printer Sharing ngừng hoạt động
- ShaPrint từng chạy rồi mất kết nối
- Cần phân biệt ICMP bị chặn vs host unreachable vs lỗi SMB/Spooler/firewall

Quy trình: **DISCOVER → DIAGNOSE → CLASSIFY → RECOMMEND → BACKUP → REPAIR → VERIFY → ROLLBACK**.

Mặc định **READ-ONLY**. Không tắt firewall hàng loạt, không bật SMB1, không reset mạng vô điều kiện.

## Công nghệ

- C# / .NET 10
- WPF (`net10.0-windows`), self-contained **multi-file** win-x64 (`PublishSingleFile=false` — EXE + runtime deps, not a single standalone EXE)
- Engine chẩn đoán tách khỏi UI; unit test bằng fake adapters
- P1.1: real collectors / safe repairs / Compare Reports — **not** FIELD READY until Win10/11 + physical LAN labs complete

## Cấu trúc

```
src/MyPC.LanPrintDoctor*     UI + modules
tests/                       Unit + integration (safe)
.github/workflows/           Windows CI
docs/                        Architecture, runbook, audit
```

## Build (Windows)

```powershell
dotnet restore MyPC.LanPrintDoctor.sln
dotnet build MyPC.LanPrintDoctor.sln -c Release
dotnet test MyPC.LanPrintDoctor.sln -c Release
dotnet publish src/MyPC.LanPrintDoctor/MyPC.LanPrintDoctor.csproj -c Release -r win-x64 --self-contained true -o artifacts/publish/win-x64
```

## Chạy nhanh

1. Trên **máy chủ**: chọn *Máy chủ* → **KIỂM TRA** → **XUẤT BÁO CÁO**
2. Trên **máy trạm**: chọn *Máy trạm*, nhập IP máy chủ → **KIỂM TRA** → **XUẤT BÁO CÁO**
3. Dùng **SO SÁNH BÁO CÁO** / CompareEngine để phân nhóm lỗi server / client / hạ tầng
4. Chỉ dùng **SỬA AN TOÀN** khi có `RepairId`, đã xem nguyên nhân, và xác nhận UAC

Báo cáo mặc định: `C:\ProgramData\MyPC\LanPrintDoctor\`

## ShaPrint

Hỗ trợ kiểm tra cổng theo tài liệu ShaPrint hiện hành:

| Port | Vai trò |
|------|---------|
| TCP 48631 | Server IPPS |
| TCP 48632 | Client loopback proxy |
| UDP 48633 | Discovery |

Không tự uninstall ShaPrint; không kết luận lỗi nếu thiếu bằng chứng.

## CI

GitHub Actions workflow `.github/workflows/windows-build.yml` chạy trên `windows-latest`: restore, build, unit/integration tests, publish, ZIP, SHA256, upload artifacts.

## Giới hạn kiểm thử

Cloud agent Linux **không** thay thế Windows Lab / máy in vật lý. Các gate Windows 10/11 lab và physical print được ghi **BLOCKED/NOT_RUN** cho đến khi chạy thật.
