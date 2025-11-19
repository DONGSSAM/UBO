import { Room } from '@/types'

interface ProjectModalProps {
  room: Room
  open: boolean
  onClose: () => void
}

export function ProjectModal({ room, open, onClose }: ProjectModalProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
      <div className="bg-white p-6 rounded-lg max-w-lg w-full overflow-x-auto">
        <h2 className="text-xl font-bold mb-4">{room.topic}</h2>

        <pre className="text-sm text-gray-700">
          {JSON.stringify(room.ai_result, null, 2)}
        </pre>

        <button
          className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded"
          onClick={onClose}
        >
          닫기
        </button>
      </div>
    </div>
  );
}