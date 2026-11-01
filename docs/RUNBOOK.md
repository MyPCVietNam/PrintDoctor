# Runbook — Server & Client

## Máy chủ (có máy in)

1. Chạy `MyPC.LanPrintDoctor.exe` (không cần Internet).
2. Chọn **Máy chủ** → **KIỂM TRA**.
3. Xem phát hiện (Public profile, Spooler, LanmanServer, firewall, ShaPrint).
4. **XUẤT BÁO CÁO** → gửi ZIP cho kỹ thuật viên.
5. Chỉ **SỬA AN TOÀN** khi RepairId rõ và đã xác nhận mạng tin cậy.

## Máy trạm

1. Chọn **Máy trạm**, nhập IP máy chủ (đúng IP đang hiện trên server).
2. **KIỂM TRA** — phân biệt:
   - ICMP fail + TCP 445 pass → nghi firewall ICMP
   - ICMP+TCP fail → chưa kết luận firewall; cần ARP/subnet/gateway/hạ tầng
3. Xuất báo cáo client.

## Khi 4 máy trạm cùng mất ping

Ưu tiên correlation (`CMP-001`): nếu server adapter/service OK mà mọi client fail → nghi **switch/AP isolation / VLAN**, không reset NIC hàng loạt.

## ShaPrint

Kiểm tra process, listen 48631/48632/48633, firewall rule ứng dụng. Không gỡ cài đặt tự động.
