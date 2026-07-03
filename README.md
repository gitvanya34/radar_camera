# radar_camera
# Анализ возможности использование камеры радара для детекции автомобилей в заданой области

## Аппаратная часть

1. Камера PHZ

Управляемая камера по двум осям камера разрешение 1920х1080 20x- optical zoom

2.   Радар
<img  width="50%" alt="1" src="https://github.com/user-attachments/assets/3658582f-aa0f-4222-94be-a19c60d0e9f1" />
<img width="50%" alt="2" src="https://github.com/user-attachments/assets/1d4bd4be-3300-4131-be30-741ff74e25cc" />

# Схема использования заложенная производителем
<img  width="50%" alt="3" src="https://github.com/user-attachments/assets/a0d61443-d56c-472d-9929-558c372ee6c6" />

[Screencast from 20.03.2026 13:15:45.webm](https://github.com/user-attachments/assets/7b2a50b3-b90e-4e5f-95cb-20f1bb05dffb)

## Перехват пакетов Wireshark

Произведен анализ трафика с радара на

```
167	42.001897	192.168.1.201	192.168.1.150	TCP	60	[TCP Retransmission] [TCP Port numbers reused] 2095 → 1000 [SYN] Seq=0 Win=1024 Len=0 MSS=1024
63	14.330013	JiangsuQ_52:30:50	Broadcast	ARP	60	ARP Announcement for 192.168.1.201
1792	7.753086655	192.168.3.168	192.168.3.166	TCP	1514	8888 → 61187 [ACK] Seq=1303698 Ack=1 Win=489 Len=1460
```


## Декомпиляция .net (Security Radar Test Host Computer)

Декомпиляция производилась через dnSpy

В классе DataAnalysis найден декодер пакета

```
Redata[i].TargetID = (float)ub[7 + 13 * i];
Redata[i].rav3 = (float)BitConverter.ToInt16(ub, 8 + 13 * i) / 100f;
Redata[i].rav1 = (float)BitConverter.ToInt16(ub, 10 + 13 * i) / 10f;
Redata[i].rav2 = (float)BitConverter.ToInt16(ub, 12 + 13 * i) / 100f;
Redata[i].xyz2 = (float)BitConverter.ToInt16(ub, 14 + 13 * i) / 10f;
Redata[i].xyz1 = (float)BitConverter.ToInt16(ub, 16 + 13 * i) / 10f;
Redata[i].rav4 = (float)BitConverter.ToInt16(ub, 18 + 13 * i) / 100f; 
```

## Формат обмена хоста с радаром

| Timestamp   | Target ID | Radial Distance (R) | Azimuth Angle | Radial Velocity (V) | Lateral Position (X) | Longitudinal Position (Y) |
|------------|-----------|---------------------|---------------|---------------------|----------------------|---------------------------|
| 0227123644 | 7         | 32.7                | -3.91         | 1.48                | -2.2                 | 32.7                      |
| 0227123644 | 7         | 32.8                | -3.91         | 1.55                | -2.2                 | 32.7                      |
| 0227123644 | 7         | 32.8                | -3.90         | 1.55                | -2.2                 | 32.8                      |

* Раз в секунду отправлятес яарп запрос с радара на предполагаемых хост о том есть ли в доступе хост устройство

*   если есть устройство то идет подбор портов в диапазоне
*   открывается передача данных

* При прошивке радара отправляется пакет с хоста на радар с параметрами в теле


Проксирование для перехвата пакетов с радара на хост

*   Прописываем в конфиге радара адрес промежуточного хоста например 192.168.3.165
*   На промежуточном хосте 192.168.3.165 запускаем скрипт перенаправления трафика по реальному хосту

```
import socket
import struct

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 1000

FORWARD_HOST = "192.168.1.151"
FORWARD_PORT = 1000


def parse_packet(data):
    if len(data) < 7:
        return

    order = struct.unpack_from("<h", data, 2)[0]
    serinum = struct.unpack_from("<h", data, 4)[0]

    print(f"\nOrder: {order}, Serial: {serinum}")

    for i in range(32):
        base = 7 + 13 * i
        if base + 12 >= len(data):
            break

        target_id = data[base]
        rav3 = struct.unpack_from("<h", data, base + 1)[0] / 100
        rav1 = struct.unpack_from("<h", data, base + 3)[0] / 10
        rav2 = struct.unpack_from("<h", data, base + 5)[0] / 100
        xyz2 = struct.unpack_from("<h", data, base + 7)[0] / 10
        xyz1 = struct.unpack_from("<h", data, base + 9)[0] / 10
        rav4 = struct.unpack_from("<h", data, base + 11)[0] / 100

        if target_id != 0:
            print(
                f"ID={target_id} "
                f"{rav1} "
                f"{rav2} "
                f"{rav4} "
                f"{xyz1} "
                f"{xyz2}"
            )


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen()

    print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    conn, addr = server.accept()
    print("Radar connected from", addr)

    with conn:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward:
            forward.connect((FORWARD_HOST, FORWARD_PORT))
            print("Connected to forward target")

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # декодируем
                parse_packet(data)

                # пересылаем дальше БЕЗ изменений
                forward.sendall(data)
```

## Параметры задаваемые радару
* RF Power Amplifier Gain — Усиление передающего сигнала радара.

* Radar Intermediate Frequency Gain — Усиление принимаемого сигнала (промежуточная частота).

* Max Radar Target Threshold — Максимальный порог сигнала для обнаружения цели.

* Min Radar Target Threshold — Минимальный порог сигнала для обнаружения цели.

* Max Target Signal-to-Noise Ratio — Максимальное допустимое отношение сигнал/шум.

* Min Target Signal-to-Noise Ratio — Минимальное отношение сигнал/шум для детекции.

* Radar Target High-Speed Threshold — Порог скорости для определения «быстрой» цели.

* Radar Speed Resolution — Разрешение измерения скорости.

* Radial Distance Resolution — Разрешение измерения дальности.

* Lateral Distance Resolution — Разрешение измерения бокового положения.

* Radar Left-Side Angle Threshold — Левый граница угла зоны обнаружения.

* Radar Right-Side Angle Threshold — Правый граница угла зоны обнаружения.

* Angle Offset Calibration — Калибровка углового смещения радара.

* Min Radar Calculation Threshold — Минимальный уровень сигнала, учитываемый при расчетах.

## Что можно сделать сейчас
* Сделать собственный обработчик пакетов с радара и калибровать его на основании камеры и дальнометр. Проввести эксперимент в комнате

На основании данных с радара скорости координат и углов можно в двумерии вычислить нахождение объекта по сути все кроме высоты его и объема

В данный момент нам доступны ограниченные параметры выдаваемые радаром из за непрозрачности работы радара и его настроек обрабатывать мы можем очень ограничено, но можно откалибровать область и провести экспериимент при помощи дальнометра

* Откалиброван радар
* Откалибрована зона камеры
* Во время детекции движения в точке на кадре радаром мы можем итерполировать радарные или камерные данные на общие объекты

```
ffplay rtsp://admin:123456@192.168.3.168:554/h264/ch1/sub/av_stream
```
