import { useState, useEffect } from 'react'
import { RoomCard } from '@/components/RoomCard'
import { ProjectModal } from '@/components/ProjectModal'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Plus, BookOpen } from 'lucide-react'

interface Room {
  id: string
  topic: string
  createdAt: string // 서버에서 ISO 문자열로 받는다고 가정
  memberCount: number
}

export default function App() {
  const [rooms, setRooms] = useState<Room[]>([])
  const [newTopic, setNewTopic] = useState('')
  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null)

  const API_URL = import.meta.env.VITE_API_URL

  // 페이지 로드 시 방 목록 가져오기
  useEffect(() => {
    fetch(`${API_URL}/rooms`)
      .then((res) => res.json())
      .then((data) => setRooms(data))
      .catch((err) => console.error('Failed to fetch rooms:', err))
  }, [])

  // 새로운 방 생성
  const handleCreateRoom = () => {
    if (!newTopic.trim()) return

    fetch(`${API_URL}/rooms`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ topic: newTopic }),
    })
      .then((res) => res.json())
      .then((newRoom) => {
        setRooms([...rooms, newRoom])
        setNewTopic('')
      })
      .catch((err) => console.error('Failed to create room:', err))
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <BookOpen className="w-8 h-8 text-indigo-600" />
            <h1 className="text-indigo-900 font-bold text-2xl">프로젝트 학습 플랫폼</h1>
          </div>
          <p className="text-gray-600">주제를 입력하고 팀과 함께 프로젝트를 진행하세요</p>
        </div>

        {/* Topic Input */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="mb-4 text-gray-900 font-semibold text-lg">새 프로젝트 시작하기</h2>
          <div className="flex gap-3">
            <Input
              placeholder="프로젝트 주제를 입력하세요..."
              value={newTopic}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setNewTopic(e.target.value)}
              onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) =>
                e.key === 'Enter' && handleCreateRoom()
              }
              className="flex-1"
            />
            <Button onClick={handleCreateRoom} className="gap-2">
              <Plus className="w-4 h-4" />
              방 만들기
            </Button>
          </div>
        </div>

        {/* Rooms Grid */}
        {rooms.length > 0 ? (
          <div className="mb-6">
            <h2 className="mb-4 text-gray-900 font-semibold text-lg">프로젝트 방 ({rooms.length})</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {rooms.map((room) => (
                <RoomCard key={room.id} room={room} onClick={() => setSelectedRoom(room)} />
              ))}
            </div>
          </div>
        ) : (
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
  )
}
