import { Room } from '@/types'

interface ProjectModalProps {
  room: Room
  open: boolean
  onClose: () => void
}

export function ProjectModal({ room, open, onClose }: ProjectModalProps) {
  if (!open) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
      <div className="bg-white p-6 rounded-lg max-w-lg w-full">
        <h2 className="text-xl font-bold mb-4">{room.topic}</h2>

        {room.ai_result ? (
          <div>
            <h3 className="font-semibold mb-2">Sections</h3>
            {room.ai_result.sections.map((sec: any, idx: number) => (
              <div key={idx} className="mb-2">
                <p className="font-medium">{sec.title}</p>
                <p>{sec.content}</p>
                {sec.references && <p className="text-sm text-gray-500">참고: {sec.references.join(", ")}</p>}
              </div>
            ))}
            <h3 className="font-semibold mt-4 mb-2">Summary</h3>
            <ul className="list-disc list-inside">
              {room.ai_result.summary.map((s: string, idx: number) => (
                <li key={idx}>{s}</li>
              ))}
            </ul>
          </div>
        ) : (
          <p>AI 결과가 없습니다.</p>
        )}

        <button className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded" onClick={onClose}>
          닫기
        </button>
      </div>
    </div>
  )
}