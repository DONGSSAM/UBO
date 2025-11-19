import { useState, useEffect } from 'react'
import { RoomCard } from '@/components/RoomCard'
import { ProjectModal } from '@/components/ProjectModal'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Plus, BookOpen } from 'lucide-react'
import { Room } from '@/types'

export default function App() {

   //상태값과 함수 적용해서 그 상태값을 동적으로 바꿈 useState사용해서, 상태값이 바뀌면 자동 랜더링
  const [rooms, setRooms] = useState<Room[]>([])//방 목록을 초기에 받아서 여기에 상태값으로 저장함
  const [newTopic, setNewTopic] = useState('')
  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null)//초기값 null 클릭 시 조건부 랜더링 projectModal 컴포넌트 보여줌

  // 환경 변수에서 API URL 가져오기
  const API_URL = import.meta.env.VITE_API_URL

  // 페이지 로드 시 방 목록 가져오기 useEffect 컴포넌트생명주기에 따라 읽어오기 함 [] - 처음 시작할 때 한 번만 실행 [값] - 값이 바뀔 때마다 실행
  useEffect(() => {
    fetch(`${API_URL}/rooms`)//백엔드 모듈 url에서 방 목록 가져오기
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
      .then((data) => {
      // data.room : 방 정보
      // data.ai_result : AI 결과
        //방 생성 요청 후 받은 방 정보 룸정보딕셔너리 + ai json 데이터, rooms 배열에 추가함
        setRooms([...rooms, { ...data.room, ai_result: data.ai_result }])
        setNewTopic('')
      })
      .catch(err => console.error('Failed to create room:', err))
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

      {/* Project Modal selectedRoom값에 따라 동적으로 해당 구문 실행 컴포넌트 랜더링 모달이랑 다름*/}
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
