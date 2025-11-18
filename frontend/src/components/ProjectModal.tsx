interface ProjectModalProps {
  room: { topic: string }; // 필요에 따라 id, memberCount 등 추가
  open: boolean;
  onClose: () => void;
}

export function ProjectModal({ room, open, onClose }: ProjectModalProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center">
      <div className="bg-white p-6 rounded">
        {room.topic}
        <button onClick={onClose}>닫기</button>
      </div>
    </div>
  );
}