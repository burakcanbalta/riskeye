#!/bin/bash

IMAGE_NAME="riskeye-scanner"
CONTAINER_NAME="riskeye-container"
VOLUME_NAME="riskeye-data"

echo "🔍 RiskEye Docker Başlatıcı"
echo "=============================="

cleanup() {
    echo "🧹 Önceki container temizleniyor..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
}

build_image() {
    echo "🐳 Docker image oluşturuluyor..."
    if docker build -t $IMAGE_NAME .; then
        echo "✅ Image başarıyla oluşturuldu: $IMAGE_NAME"
    else
        echo "❌ Image oluşturma başarısız!"
        exit 1
    fi
}

check_ports() {
    if netstat -tuln | grep -q ":5000 "; then
        echo "⚠️  Port 5000 zaten kullanımda! Mevcut uygulama kapatılıyor..."
        pkill -f "python.*riskeye" 2>/dev/null || true
        sleep 2
    fi
}

create_volume() {
    if ! docker volume ls | grep -q $VOLUME_NAME; then
        echo "💾 Veri volume'ü oluşturuluyor..."
        docker volume create $VOLUME_NAME
    fi
}

start_container() {
    echo "🚀 Container başlatılıyor..."
    
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p 5000:5000 \
        -v $VOLUME_NAME:/app/scan_results \
        -e FLASK_ENV=production \
        -e PYTHONUNBUFFERED=1 \
        --security-opt=no-new-privileges \
        $IMAGE_NAME

    if [ $? -eq 0 ]; then
        echo "✅ Container başlatıldı: $CONTAINER_NAME"
    else
        echo "❌ Container başlatılamadı!"
        exit 1
    fi
}

show_logs() {
    echo "📊 Container logları gösteriliyor (Ctrl+C ile çıkabilirsiniz)..."
    sleep 2
    docker logs -f $CONTAINER_NAME
}

check_status() {
    echo "⏳ Container durumu kontrol ediliyor..."
    sleep 5
    
    if docker ps | grep -q $CONTAINER_NAME; then
        echo "✅ RiskEye başarıyla çalışıyor!"
        echo "🌐 Tarayıcınızda açın: http://localhost:5000"
        echo ""
        echo "📋 Kullanım:"
        echo "   Logları görüntüle: docker logs -f $CONTAINER_NAME"
        echo "   Durdur: docker stop $CONTAINER_NAME"
        echo "   Başlat: docker start $CONTAINER_NAME"
        echo "   Restart: docker restart $CONTAINER_NAME"
    else
        echo "❌ Container çalışmıyor! Logları kontrol edin:"
        docker logs $CONTAINER_NAME
        exit 1
    fi
}

main() {
    case "${1:-}" in
        "stop")
            echo "🛑 RiskEye durduruluyor..."
            docker stop $CONTAINER_NAME 2>/dev/null && echo "✅ Durduruldu" || echo "❌ Zaten çalışmıyor"
            exit 0
            ;;
        "restart")
            echo "🔄 RiskEye yeniden başlatılıyor..."
            docker restart $CONTAINER_NAME 2>/dev/null && echo "✅ Yeniden başlatıldı" || echo "❌ Container bulunamadı"
            exit 0
            ;;
        "logs")
            docker logs -f $CONTAINER_NAME 2>/dev/null || echo "❌ Container bulunamadı veya çalışmıyor"
            exit 0
            ;;
        "status")
            if docker ps | grep -q $CONTAINER_NAME; then
                echo "✅ RiskEye çalışıyor - http://localhost:5000"
            else
                echo "❌ RiskEye çalışmıyor"
            fi
            exit 0
            ;;
    esac

    echo "🔍 Mevcut container kontrol ediliyor..."
    
    if docker ps -a | grep -q $CONTAINER_NAME; then
        echo "📦 Mevcut container bulundu: $CONTAINER_NAME"
        read -p "🔄 Yeniden oluşturulsun mu? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cleanup
        else
            echo "♻️ Mevcut container başlatılıyor..."
            docker start $CONTAINER_NAME
            check_status
            show_logs
            exit 0
        fi
    fi

    if [[ "$(docker images -q $IMAGE_NAME 2>/dev/null)" == "" ]]; then
        build_image
    else
        echo "📦 Image zaten mevcut: $IMAGE_NAME"
        read -p "🔁 Image yeniden oluşturulsun mu? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            build_image
        fi
    fi

    check_ports
    create_volume
    start_container
    check_status
    
    read -p "📊 Logları görüntülemek ister misiniz? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        show_logs
    fi
}

main "$@"
