#!/usr/bin/env python3
import pika
from waggle.coresense.utils import decode_frame


connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

result = channel.queue_declare(exclusive=True)
queue = result.method.queue
channel.queue_bind(queue=queue, exchange='data.fanout')


def callback(ch, method, properties, body):
    if properties.app_id.startswith('coresense'):
        data = decode_frame(body)

        if 'Coresense ID' in data:
            print('coresense_id', data['Coresense ID']['mac_address'].lower())

        if 'Chemsense ID' in data:
            print('chemsense_id', data['Chemsense ID']['mac_address'].lower())

        channel.stop_consuming()


channel.basic_consume(callback, queue=queue, no_ack=True)
channel.start_consuming()

