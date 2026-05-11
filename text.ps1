while ($true) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("10.88.202.59", 9997)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $result = $reader.ReadLine()
        Write-Host "$(Get-Date) 认证结果: $result"
        $client.Close()
    } catch {
        Write-Host "连接失败"
    }
    Start-Sleep -Seconds 1   # 间隔 1 秒防止刷爆
}