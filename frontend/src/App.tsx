import { useState } from 'react';
import { RoomCard } from '@/components/RoomCard';
import { ProjectModal } from '@/components/ProjectModal';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Plus, BookOpen } from 'lucide-react';

interface Room {
  id: string;
  topic: string;
  createdAt: Date;
  memberCount: number;
}

export default function App() {
  const [rooms, setRooms] = useState<Room[]>([
    {
      id: '1',
      topic: '기후 변화와 환경 보호',
      createdAt: new Date('2024-11-15'),
      memberCount: 4
    },
    {
      id: '2',
      topic: 'AI와 미래 사회',
      createdAt: new Date('2024-11-16'),
      memberCount: 3
    }
  ]);
  const [newTopic, setNewTopic] = useState('');
  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null);

  const handleCreateRoom = () => {
    if (newTopic.trim()) {
      const newRoom: Room = {
        id: Date.now().toString(),
        topic: newTopic,
        createdAt: new Date(),
        memberCount: 1
      };
      setRooms([...rooms, newRoom]);
      setNewTopic('');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <BookOpen className="w-8 h-8 text-indigo-600" />
            <h1 className="text-indigo-900">프로젝트 학습 플랫폼</h1>
          </div>
          <p className="text-gray-600">주제를 입력하고 팀과 함께 프로젝트를 진행하세요</p>
        </div>

        {/* Topic Input */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="mb-4 text-gray-900">새 프로젝트 시작하기</h2>
          <div className="flex gap-3">
            <Input
              placeholder="프로젝트 주제를 입력하세요..."
              value={newTopic}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setNewTopic(e.target.value)}
              onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => e.key === 'Enter' && handleCreateRoom()}
              className="flex-1"
            />
            <Button onClick={handleCreateRoom} className="gap-2">
              <Plus className="w-4 h-4" />
              방 만들기
            </Button>
          </div>
        </div>

        {/* Rooms Grid */}
        <div className="mb-6">
          <h2 className="mb-4 text-gray-900">프로젝트 방 ({rooms.length})</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {rooms.map((room) => (
              <RoomCard
                key={room.id}
                room={room}
                onClick={() => setSelectedRoom(room)}
              />
            ))}
          </div>
        </div>

        {rooms.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <BookOpen className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p>아직 생성된 프로젝트 방이 없습니다.</p>
            <p>위에서 주제를 입력하여 새로운 방을 만들어보세요!</p>
          </div>
        )}
      </div>

      {/* Project Modal */}
      {selectedRoom && (
        <ProjectModal
          room={selectedRoom}
          open={!!selectedRoom}
          onClose={() => setSelectedRoom(null)}
        />
      )}
    </div>
  );
}
