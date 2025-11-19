import React from 'react';
import { Room } from '@/types';

interface RoomCardProps {
  room: Room;
  onClick: () => void;
}

export function RoomCard({ room, onClick }: RoomCardProps) {
  return (
    <div onClick={onClick} className="p-4 bg-white rounded shadow cursor-pointer">
      <h3 className="font-semibold">{room.topic}</h3>
      {/* JSON 전체를 문자열로 표시 */}
      <pre className="text-sm text-gray-700 overflow-x-auto">
        {JSON.stringify(room.ai_result, null, 2)}
      </pre>
    </div>
  );
}