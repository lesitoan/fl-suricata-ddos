# Phạm vi bản laptop

Đọc README.md và scripts/README.md trước khi tiếp tục. docs/ và TASK_LOG.md là tài liệu nội bộ được Git bỏ qua; chỉ đọc thêm nếu tồn tại tại máy hiện tại. Mô tả đề tài gốc trong docs/ (nếu có) là tài liệu tham chiếu; yêu cầu trực tiếp của người dùng quyết định phạm vi thao tác.

- Chỉ thay đổi bản laptop trong thư mục này. ddos-fl-project, ddos-fl-production, các node remote và hệ thống đang chạy chỉ được đọc tham khảo trừ khi người dùng yêu cầu riêng.
- Không gọi wrapper SSH/deploy cũ, không đổi Tailscale, Cloudflare, firewall, Docker daemon hay restart hệ thống để triển khai bản này.
- Dùng Compose project ddos-fl-laptop với container/network/volume riêng. Kiểm tên project, mount và đường dẫn trước mọi mutation. Không mount Docker socket, thư mục gốc host hoặc toàn bộ dữ liệu tất cả node vào FL client/server.
- Mỗi client chỉ đọc dữ liệu riêng; server không mount dataset. Client trao đổi parameters và metadata/metrics cần thiết. Không khẳng định FL tự bảo đảm riêng tư tuyệt đối.
- Phân biệt artifact tham khảo với kết quả mới. Không ghi DONE, đã hội tụ, realtime hoặc LDAP reflection khi chưa có evidence tương ứng.
- Traffic demo chỉ nằm trong mạng lab Docker riêng, với thời lượng/tốc độ giới hạn. Không phát attack ra Internet, LAN đang dùng hoặc deployment cũ. LDAP/UDP cần phân biệt bằng payload/nguồn nhãn, không chỉ dựa vào transport.
- Nếu có TASK_LOG.md nội bộ, cập nhật sau thay đổi đáng kể và liên kết evidence. Không phụ thuộc tài liệu nội bộ bị Git bỏ qua để cài/chạy source. File kế hoạch không phải bằng chứng triển khai.
