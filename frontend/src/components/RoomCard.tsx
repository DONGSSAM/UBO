export function RoomCard({ room, onClick }: any) {
  return (
    <div onClick={onClick} className="p-4 bg-white rounded shadow">
      {room.topic}
    </div>
  );
}